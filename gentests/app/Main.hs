{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}

module Main where

import           Control.Monad          (replicateM)
import qualified Data.ByteString.Char8  as BC
import qualified Data.ByteString.Lazy   as BL
import           Data.List              (intercalate)
import           Data.Maybe             (isJust)
import           Network.MQTT.Arbitrary
import           Network.MQTT.Types     as MT
import           Numeric                (showHex)
import           Test.QuickCheck        as QC
import           Text.RawString.QQ

hexa :: BL.ByteString -> String
hexa b
  | BL.null b = "0"
  | otherwise = (intercalate ", " . map (\x -> "0x" <> showHex x "") . BL.unpack) b

bool :: Bool -> String
bool True  = "true"
bool False = "false"

qos :: QoS -> String
qos QoS0 = "LWMQTT_QOS0"
qos QoS1 = "LWMQTT_QOS1"
qos QoS2 = "LWMQTT_QOS2"

protlvl :: ProtocolLevel -> String
protlvl Protocol311 = "LWMQTT_MQTT311"
protlvl Protocol50  = "LWMQTT_MQTT5"

shortprot :: ProtocolLevel -> String
shortprot Protocol311 = "311"
shortprot Protocol50  = "5"

v311PubReq :: PublishRequest -> PublishRequest
v311PubReq p50 = let (PublishPkt p) = v311mask (PublishPkt p50) in p

v311SubReq :: SubscribeRequest -> SubscribeRequest
v311SubReq p50 = let (SubscribePkt p) = v311mask (SubscribePkt p50) in p

v311SubACKReq :: SubscribeResponse -> SubscribeResponse
v311SubACKReq p50 = let (SubACKPkt p) = v311mask (SubACKPkt p50) in p

v311ConnReq :: ConnectRequest -> ConnectRequest
v311ConnReq p50 = let (ConnPkt p) = v311mask (ConnPkt p50) in p

userFix :: ConnectRequest -> ConnectRequest
userFix = ufix . pfix
  where
    ufix p@ConnectRequest{..}
      | _username == Just "" = p{_username=Nothing}
      | otherwise = p
    pfix p@ConnectRequest{..}
      | _password == Just "" = p{_password=Nothing}
      | otherwise = p

data Prop = IProp Int String Int
          | SProp Int String (Int,BL.ByteString)
          | UProp Int (Int,BL.ByteString) (Int,BL.ByteString)

captureProps :: [MT.Property] -> [Prop]
captureProps = map e
  where
    peW8 i x = IProp i "byte" (fromEnum x)
    peW16 i x = IProp i "int16" (fromEnum x)
    peW32 i x = IProp i "int32" (fromEnum x)
    peUTF8 i x = SProp i "str" (0,x)
    peBin i x = SProp i "str" (0,x)
    peVarInt i = IProp i "varint"
    pePair i k v = UProp i (0,k) (0,v)

    e (PropPayloadFormatIndicator x)          = peW8 0x01 x
    e (PropMessageExpiryInterval x)           = peW32 0x02 x
    e (PropContentType x)                     = peUTF8 0x03 x
    e (PropResponseTopic x)                   = peUTF8 0x08 x
    e (PropCorrelationData x)                 = peBin 0x09 x
    e (PropSubscriptionIdentifier x)          = peVarInt 0x0b x
    e (PropSessionExpiryInterval x)           = peW32 0x11 x
    e (PropAssignedClientIdentifier x)        = peUTF8 0x12 x
    e (PropServerKeepAlive x)                 = peW16 0x13 x
    e (PropAuthenticationMethod x)            = peUTF8 0x15 x
    e (PropAuthenticationData x)              = peBin 0x16 x
    e (PropRequestProblemInformation x)       = peW8 0x17 x
    e (PropWillDelayInterval x)               = peW32 0x18 x
    e (PropRequestResponseInformation x)      = peW8 0x19 x
    e (PropResponseInformation x)             = peUTF8 0x1a x
    e (PropServerReference x)                 = peUTF8 0x1c x
    e (PropReasonString x)                    = peUTF8 0x1f x
    e (PropReceiveMaximum x)                  = peW16 0x21 x
    e (PropTopicAliasMaximum x)               = peW16 0x22 x
    e (PropTopicAlias x)                      = peW16 0x23 x
    e (PropMaximumQoS x)                      = peW8 0x24 x
    e (PropRetainAvailable x)                 = peW8 0x25 x
    e (PropUserProperty k v)                  = pePair 0x26 k v
    e (PropMaximumPacketSize x)               = peW32 0x27 x
    e (PropWildcardSubscriptionAvailable x)   = peW8 0x28 x
    e (PropSubscriptionIdentifierAvailable x) = peW8 0x29 x
    e (PropSharedSubscriptionAvailable x)     = peW8 0x2a x

-- Emit the given list of properties as C code.
genProperties :: String -> [MT.Property] -> String
genProperties name props = mconcat [
  "  ", encodePropList, "\n",
  "  lwmqtt_properties_t ", name, " = {" <> show (length props) <> ", (lwmqtt_property_t*)&", name, "list};\n"
  ]

  where
    encodePropList = let (hdr, cp) = (emitByteArrays . captureProps) props in
                       mconcat (map (<>"\n  ") hdr) <> "\n"
                       <> "  lwmqtt_property_t " <> name <> "list[] = {\n"
                       <> mconcat (map (indent.e) cp)
                       <> "  };\n"
      where
        emitByteArrays :: [Prop] -> ([String], [Prop])
        emitByteArrays = go [] [] 0
          where
            go :: [String] -> [Prop] -> Int -> [Prop] -> ([String], [Prop])
            go l p _ []     = (reverse l, reverse p)
            go l p n (x@IProp{}:xs) = go l (x:p) n xs
            go l p n (SProp i s (_,bs):xs) = go (newstr n bs:l) (SProp i s (n,bs):p) (n+1) xs
            go l p n (UProp i (_,bs1) (_,bs2):xs) = go (newstr n bs1 : newstr (n+1) bs2 : l) (UProp i (n,bs1) (n+1,bs2):p) (n+2) xs

            newstr n s = "uint8_t bytes" <> name <> show n <> "[] = {" <> hexa s <> "};"

        e :: Prop -> String
        e (IProp i n v) = prop i n (show v)
        e (SProp i n (x,xv)) = prop i n (b x xv)
        e (UProp i (k,kv) (v,vv)) = prop i "pair" ("{.k=" <> b k kv <> ", .v=" <> b v vv <> "}")

        prop i n v = "{.prop = (lwmqtt_prop_t)" <> show i <> ", .value = {." <> n <> " = " <> v <> "}},\n"

        indent = ("    " <>)

        b x xv = "{" <> show (BL.length xv) <> ", (char*)&bytes" <> name <> show x <> "}"

encodeString :: String -> BL.ByteString -> String
encodeString name bytes = mconcat [
  "  uint8_t " <> name <> "_bytes[] = {" <> hexa bytes <> "};\n",
  "  lwmqtt_string_t " <> name <> " = {" <> show (BL.length bytes) <> ", (char*)&" <> name <> "_bytes};\n"
  ]

genTestFunc :: (Show a, ByteMe a) => String -> String -> ProtocolLevel -> Int -> a -> String -> String
genTestFunc tset tname prot i p body = let e = toByteString prot p in
                                         mconcat [
  "// ", show p, "\n",
  "TEST(", tset, shortprot prot, "QCTest, ", tname, show i <> ") {\n",
  "uint8_t pkt[] = {" <> hexa e <> "};\n",
  body, "\n",
  "}\n\n"
  ]

genPublishTest :: ProtocolLevel -> Int -> PublishRequest -> String
genPublishTest prot i p@PublishRequest{..} =
  mconcat [encTest, decTest]

  where
    encTest = genTestFunc "Publish" "Encode" prot i p $ mconcat [
      encodeString "topic" _pubTopic,
      "\n  uint8_t buf[sizeof(pkt)+10] = { 0 };\n",
      "lwmqtt_message_t msg = lwmqtt_default_message;\n",
      "msg.qos = " <> qos _pubQoS <> ";\n",
      "msg.retained = " <> bool _pubRetain <> ";\n",
      "uint8_t msg_bytes[] = {" <> hexa _pubBody <> "};\n",
      "msg.payload = (unsigned char*)&msg_bytes;\n",
      "msg.payload_len = " <> show (BL.length _pubBody) <> ";\n\n",
      genProperties "props" _pubProps,
      "size_t len = 0;\n",
      "lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(buf), &len, " <> protlvl prot <> ", ",
      bool _pubDup, ", ", show _pubPktID,  ", topic, msg, props);\n\n",
      "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
      "EXPECT_ARRAY_EQ(pkt, buf, len);"
      ]

    decTest = genTestFunc "Publish" "Decode" prot i p $ mconcat [
        "bool dup;\n",
        "uint16_t packet_id;\n",
        "lwmqtt_string_t topic;\n",
        "lwmqtt_message_t msg;\n",
        "lwmqtt_serialized_properties_t props;\n",
        "lwmqtt_err_t err = lwmqtt_decode_publish(pkt, sizeof(pkt), ", protlvl prot, ", &dup, &packet_id, &topic, &msg, &props);\n",
        "\n",
        "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
        encodeString "exp_topic" _pubTopic,
        encodeString "exp_body" _pubBody,
        "EXPECT_EQ(dup, ", bool _pubDup, ");\n",
        "EXPECT_EQ(msg.qos, ", qos _pubQoS, ");\n",
        "EXPECT_EQ(msg.retained, ", bool _pubRetain, ");\n",
        "EXPECT_EQ(packet_id, ", show _pubPktID, ");\n",
        "EXPECT_ARRAY_EQ(exp_topic_bytes, reinterpret_cast<uint8_t*>(topic.data), ", show (BL.length _pubTopic), ");\n",
        "EXPECT_EQ(msg.payload_len, ", show (BL.length _pubBody), ");\n",
        "EXPECT_ARRAY_EQ(exp_body_bytes, msg.payload, ", show (BL.length _pubBody), ");\n",
        "lwmqtt_string_t x = exp_topic;\nx = exp_body;\n"
        ]


genSubTest :: ProtocolLevel -> Int -> SubscribeRequest -> String
genSubTest prot i p@(SubscribeRequest pid subs props) = do
  genTestFunc "Subscribe" "Encode" prot i p $ mconcat [
    "uint8_t buf[sizeof(pkt)+10] = { 0 };\n",
    encodeFilters,
    encodeQos,
    genProperties "props" props,
    "  size_t len = 0;\n",
    "  lwmqtt_err_t err = lwmqtt_encode_subscribe(buf, sizeof(buf), &len, ", protlvl prot, ", ",
    show pid, ", ", show (length subs),  ", topic_filters, sub_opts, props);\n\n",
    "  EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "  EXPECT_ARRAY_EQ(pkt, buf, len);\n"
    ]

  where
    encodeFilters = "lwmqtt_string_t topic_filters[" <> show (length subs) <> "];\n" <>
                    concatMap aSub (zip [0..] subs)
      where
        aSub :: (Int, (BL.ByteString, SubOptions)) -> String
        aSub (i', (s,_)) = mconcat [
          encodeString ("topic_filter_s" <> show i') s,
          "topic_filters[", show i', "] = topic_filter_s", show i', ";\n"
          ]

    encodeQos = "lwmqtt_sub_options_t sub_opts["<> show (length subs) <> "];\n" <> (concatMap subvals $ zip [0..] subs)
      where
        subvals :: (Int,(BL.ByteString, SubOptions)) -> String
        subvals (subi,(_,SubOptions{..})) = mconcat [
          si, "qos = ", qos _subQoS, ";\n",
          si, "retain_handling = ", rh _retainHandling, ";\n",
          si, "retain_as_published = ", bool _retainAsPublished, ";\n",
          si, "no_local = ", bool _noLocal, ";\n"
          ]
          where
            si = "sub_opts[" <> show subi <> "]."
            rh SendOnSubscribe      = "LWMQTT_SUB_SEND_ON_SUB"
            rh SendOnSubscribeNew   = "LWMQTT_SUB_SEND_ON_SUB_NEW"
            rh DoNotSendOnSubscribe = "LWMQTT_SUB_NO_SEND_ON_SUB"

genConnectTest :: ProtocolLevel -> Int -> ConnectRequest -> String
genConnectTest prot i p@ConnectRequest{..} = do
  genTestFunc "Connect" "Encode" prot i p $ mconcat [
    "uint8_t buf[sizeof(pkt)+10] = { 0 };\n",

    genProperties "props" _properties,
    encodeWill _lastWill,
    encodeOptions,
    "size_t len = 0;\n",
    "lwmqtt_err_t err = lwmqtt_encode_connect(buf, sizeof(buf), &len, " <> protlvl prot <> ", opts, ",
    if isJust _lastWill then "&will" else "NULL", ");\n\n",
    "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "EXPECT_EQ(len, sizeof(pkt));\n",
    "EXPECT_ARRAY_EQ(pkt, buf, len);\n"
    ]

  where
    encodeWill Nothing = ""
    encodeWill (Just LastWill{..}) = mconcat [
      "lwmqtt_will_t will = lwmqtt_default_will;\n",
      genProperties "willprops" _willProps,
      encodeString "will_topic" _willTopic,
      encodeString "will_payload" _willMsg,
      "will.topic = will_topic;\n",
      "will.payload   = will_payload;\n",
      "will.qos = " <> qos _willQoS <> ";\n",
      "will.retained = " <> bool _willRetain <> ";\n",
      "will.properties = willprops;\n"
      ]

    encodeOptions = mconcat [
      "lwmqtt_options_t opts = lwmqtt_default_options;\n",
      "opts.properties = props;\n",
      "opts.clean_session = " <> bool _cleanSession <> ";\n",
      "opts.keep_alive = " <> show _keepAlive <> ";\n",
      encodeString "client_id" _connID,
      "opts.client_id = client_id;\n",
      maybeString "username" _username,
      maybeString "password" _password
      ]

      where maybeString _ Nothing = ""
            maybeString n (Just b) = mconcat [
              encodeString n b,
              "opts.", n, " = ", n, ";\n"
              ]

genSubACKTest :: ProtocolLevel -> Int -> SubscribeResponse -> String
genSubACKTest prot i p@(SubscribeResponse pid res _props) = do
  let ll = show (length res)
  genTestFunc "SubACK" "Decode" prot i p $ mconcat [
    "uint16_t packet_id;\n",
    "int count;\n",
    "lwmqtt_qos_t granted_qos_levels[", ll, "];\n",
    "lwmqtt_err_t err = lwmqtt_decode_suback(pkt, sizeof(pkt), &packet_id,",
    protlvl prot, ", ", ll, ", &count, granted_qos_levels);\n",
    "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "EXPECT_EQ(packet_id, ", show pid, ");\n",
    "EXPECT_EQ(count, ", ll, ");\n",
    concatMap checkQos (zip [0..] res)
    ]

    where
      checkQos :: (Int,Either SubErr QoS) -> String
      checkQos (qi,q) = "EXPECT_EQ(granted_qos_levels[" <> show qi <> "], " <> qq prot q <> ");\n"
      qq Protocol311 (Left _) = "0x80"
      qq Protocol50 (Left x)  = q5 x
      qq _ (Right q)          = qos q

      q5 SubErrUnspecifiedError                    =  "0x80"
      q5 SubErrImplementationSpecificError         =  "0x83"
      q5 SubErrNotAuthorized                       =  "0x87"
      q5 SubErrTopicFilterInvalid                  =  "0x8F"
      q5 SubErrPacketIdentifierInUse               =  "0x91"
      q5 SubErrQuotaExceeded                       =  "0x97"
      q5 SubErrSharedSubscriptionsNotSupported     =  "0x9E"
      q5 SubErrSubscriptionIdentifiersNotSupported =  "0xA1"
      q5 SubErrWildcardSubscriptionsNotSupported   =  "0xA2"

main :: IO ()
main = do
  putStrLn [r|#include <gtest/gtest.h>

extern "C" {
#include <lwmqtt.h>
#include "../src/packet.h"
}

#ifdef __GNUC__
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wc99-extensions"
#else
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#endif

#define EXPECT_ARRAY_EQ(reference, actual, element_count)                 \
  {                                                                       \
    for (size_t cmp_i = 0; cmp_i < element_count; cmp_i++) {              \
      EXPECT_EQ(reference[cmp_i], actual[cmp_i]) << "At byte: " << cmp_i; \
    }                                                                     \
  }
|]
  let numTests = 30

  pubs <- replicateM numTests $ generate arbitrary
  f genPublishTest Protocol311 (v311PubReq <$> pubs)
  f genPublishTest Protocol50 pubs

  conns <- replicateM numTests $ generate arbitrary
  f genConnectTest Protocol311 (userFix . v311ConnReq <$> conns)
  f genConnectTest Protocol50 (userFix <$> conns)

  subs <- replicateM numTests $ generate arbitrary
  f genSubTest Protocol311 (v311SubReq <$> subs)
  f genSubTest Protocol50 subs

  subax <- replicateM numTests $ generate arbitrary
  f genSubACKTest Protocol311 (v311SubACKReq <$> subax)
  f genSubACKTest Protocol50 subax


  where
    f :: (ProtocolLevel -> Int -> a -> String) -> ProtocolLevel -> [a] -> IO ()
    f g pl l = mapM_ putStrLn $ map (uncurry $ g pl) $ zip [1..] l

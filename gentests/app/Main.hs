{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}

module Main where

import           Control.Monad          (replicateM)
import qualified Data.ByteString.Char8  as BC
import qualified Data.ByteString.Lazy   as BL
import           Data.List              (intercalate)
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

v311PubReq :: PublishRequest -> PublishRequest
v311PubReq p50 = let (PublishPkt p) = v311mask (PublishPkt p50) in p

genPublish311Test :: Int -> PublishRequest -> IO ()
genPublish311Test i p@PublishRequest{..} = do
  let e = toByteString Protocol311 p

  putStrLn $ "// " <> show p
  putStrLn $ "TEST(Publish311QCTest, Encode" <> show i <> ") {"
  putStrLn $ "  uint8_t pkt[] = {" <> hexa e <> "};"

  putStrLn $ "\n  uint8_t buf[" <> show (BL.length e + 10) <> "] = { 0 };\n"

  putStrLn . mconcat $ [
    "  uint8_t topic_bytes[] = {" <> hexa _pubTopic <> "};\n",
    "  lwmqtt_string_t topic = { " <> show (BL.length _pubTopic) <> ", (char*)&topic_bytes};\n",
    "  lwmqtt_message_t msg = lwmqtt_default_message;\n",
    "  msg.qos = " <> qos _pubQoS <> ";\n",
    "  msg.retained = " <> bool _pubRetain <> ";\n",
    "  uint8_t msg_bytes[] = {" <> hexa _pubBody <> "};\n",
    "  msg.payload = (unsigned char*)&msg_bytes;\n",
    "  msg.payload_len = " <> show (BL.length _pubBody) <> ";\n\n",
    "  size_t len = 0;\n",
    "  lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(buf), &len, LWMQTT_MQTT311, ",
    bool _pubDup, ", ", show _pubPktID,  ", topic, msg, empty_props);\n\n",
    "  EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "  EXPECT_ARRAY_EQ(pkt, buf, len);"
    ]
  putStrLn "}\n"

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
    peVarInt i x = IProp i "varint" x
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

emitByteArrays :: [Prop] -> ([String], [Prop])
emitByteArrays = go [] [] 0
  where
    go :: [String] -> [Prop] -> Int -> [Prop] -> ([String], [Prop])
    go l p _ []     = (reverse l, reverse p)
    go l p n ((x@IProp{}):xs) = go l (x:p) n xs
    go l p n ((SProp i s (_,bs)):xs) = go (newstr n bs:l) (SProp i s (n,bs):p) (n+1) xs
    go l p n ((UProp i (_,bs1) (_,bs2)):xs) = go (newstr n bs1 : newstr (n+1) bs2 : l) (UProp i (n,bs1) (n+1,bs2):p) (n+2) xs

    newstr n s = "uint8_t bytes" <> show n <> "[] = {" <> hexa s <> "};"

encodePropList :: [MT.Property] -> String
encodePropList props = let (hdr, cp) = (emitByteArrays . captureProps) props in
                         mconcat (map (<>"\n  ") hdr) <> "\n"
                         <> "  lwmqtt_property_t proplist[] = {\n"
                         <> mconcat (map (indent.e) cp)
                         <> "  };\n"
  where
    e :: Prop -> String
    e (IProp i n v) = prop i n (show v)
    e (SProp i n (x,xv)) = prop i n (b x xv)
    e (UProp i (k,kv) (v,vv)) = prop i "pair" ("{.k=" <> b k kv <> ", .v=" <> b v vv <> "}")

    prop i n v = "{.prop = (lwmqtt_prop_t)" <> show i <> ", .value = {." <> n <> " = " <> v <> "}},\n"

    indent = ("    " <>)

    b x xv = "{" <> show (BL.length xv) <> ", (char*)&bytes" <> show x <> "}"

    p :: [BL.ByteString] -> [String]
    p = map (map (toEnum . fromEnum) . BL.unpack)

genPublish50Test :: Int -> PublishRequest -> IO ()
genPublish50Test i p@PublishRequest{..} = do
  let e = toByteString Protocol50 p

  putStrLn $ "// " <> show p
  putStrLn $ "TEST(Publish50QCTest, Encode" <> show i <> ") {"
  putStrLn $ "  uint8_t pkt[] = {" <> hexa e <> "};"

  putStrLn $ "\n  uint8_t buf[" <> show (BL.length e + 10) <> "] = { 0 };\n"

  putStrLn . mconcat $ [
    "  uint8_t topic_bytes[] = {" <> hexa _pubTopic <> "};\n",
    "  lwmqtt_string_t topic = { " <> show (BL.length _pubTopic) <> ", (char*)&topic_bytes};\n",
    "  lwmqtt_message_t msg = lwmqtt_default_message;\n",
    "  msg.qos = " <> qos _pubQoS <> ";\n",
    "  msg.retained = " <> bool _pubRetain <> ";\n",
    "  uint8_t msg_bytes[] = {" <> hexa _pubBody <> "};\n",
    "  msg.payload = (unsigned char*)&msg_bytes;\n",
    "  msg.payload_len = " <> show (BL.length _pubBody) <> ";\n\n",
    "  ", encodePropList _pubProps, "\n",
    "  lwmqtt_properties_t props = {" <> show (length _pubProps) <> ", (lwmqtt_property_t*)&proplist};\n",
    "  size_t len = 0;\n",
    "  lwmqtt_err_t err = lwmqtt_encode_publish(buf, sizeof(buf), &len, LWMQTT_MQTT5, ",
    bool _pubDup, ", ", show _pubPktID,  ", topic, msg, props);\n\n",
    "  EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "  EXPECT_ARRAY_EQ(pkt, buf, len);"
    ]
  putStrLn "}\n"


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

static lwmqtt_properties_t empty_props = lwmqtt_empty_props;

#define EXPECT_ARRAY_EQ(reference, actual, element_count)                 \
  {                                                                       \
    for (size_t cmp_i = 0; cmp_i < element_count; cmp_i++) {              \
      EXPECT_EQ(reference[cmp_i], actual[cmp_i]) << "At byte: " << cmp_i; \
    }                                                                     \
  }
|]
  x <- replicateM 100 $ generate arbitrary
  mapM_ (\(i,p) -> genPublish311Test i (v311PubReq p)) $ zip [1..] x
  mapM_ (uncurry genPublish50Test) $ zip [1..] x
  genPublish50Test 0 (PublishRequest{
                       _pubTopic = "surgemq",
                       _pubBody = "send me home",
                       _pubRetain = True,
                       _pubQoS = QoS1,
                       _pubDup = False,
                       _pubPktID = 0,
                       _pubProps = [PropMessageExpiryInterval 33,
                                    PropReasonString "a reason"]})

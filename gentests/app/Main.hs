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

data PubACKs = ACK PubACK | REC PubREC | REL PubREL | COMP PubCOMP deriving(Show, Eq)

instance Arbitrary PubACKs where
  arbitrary = oneof [
    ACK <$> arbitrary,
    REC <$> arbitrary,
    REL <$> arbitrary,
    COMP <$> arbitrary
    ]

v311ACKs :: PubACKs -> PubACKs
v311ACKs (ACK p50)  = let (PubACKPkt a) = v311mask (PubACKPkt p50) in ACK a
v311ACKs (REC p50)  = let (PubRECPkt a) = v311mask (PubRECPkt p50) in REC a
v311ACKs (REL p50)  = let (PubRELPkt a) = v311mask (PubRELPkt p50) in REL a
v311ACKs (COMP p50) = let (PubCOMPPkt a) = v311mask (PubCOMPPkt p50) in COMP a

v311SubReq :: SubscribeRequest -> SubscribeRequest
v311SubReq p50 = let (SubscribePkt p) = v311mask (SubscribePkt p50) in p

v311UnsubReq :: UnsubscribeRequest -> UnsubscribeRequest
v311UnsubReq p50 = let (UnsubscribePkt p) = v311mask (UnsubscribePkt p50) in p

v311SubACK :: SubscribeResponse -> SubscribeResponse
v311SubACK p50 = let (SubACKPkt p) = v311mask (SubACKPkt p50) in p

v311UnsubACK :: UnsubscribeResponse -> UnsubscribeResponse
v311UnsubACK p50 = let (UnsubACKPkt p) = v311mask (UnsubACKPkt p50) in p

v311ConnReq :: ConnectRequest -> ConnectRequest
v311ConnReq p50 = let (ConnPkt p) = v311mask (ConnPkt p50) in p

v311DiscoClean :: DisconnectRequest -> DisconnectRequest
v311DiscoClean p50 = let (DisconnectPkt p) = v311mask (DisconnectPkt p50) in p

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
    peVarInt i = IProp i "int32"
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

genUnsubTest :: ProtocolLevel -> Int -> UnsubscribeRequest -> String
genUnsubTest prot i p@(UnsubscribeRequest pid subs props) = do
  genTestFunc "Unsubscribe" "Encode" prot i p $ mconcat [
    "uint8_t buf[sizeof(pkt)+10] = { 0 };\n",
    genProperties "props" props,
    encodeFilters,
    "size_t len;\n",
    "lwmqtt_err_t err = lwmqtt_encode_unsubscribe(buf, sizeof(buf), &len, ", protlvl prot, ", ", show pid, ", ",
    show (length subs), ", topic_filters, props);\n",
    "  EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "  EXPECT_ARRAY_EQ(pkt, buf, len);\n"
    ]
  where
    encodeFilters = "lwmqtt_string_t topic_filters[" <> show (length subs) <> "];\n" <>
                    concatMap aSub (zip [0..] subs)
      where aSub :: (Int, BL.ByteString) -> String
            aSub (i', t) = mconcat [
              encodeString ("topic_filter_s" <> show i') t,
              "topic_filters[", show i', "] = topic_filter_s", show i', ";\n"
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

genUnsubACKTest :: ProtocolLevel -> Int -> UnsubscribeResponse -> String
genUnsubACKTest prot i p@(UnsubscribeResponse pid _props res) = do
  let ll = show (length res)
  genTestFunc "UnsubACK" "Decode" prot i p $ mconcat [
    "uint16_t packet_id;\n",
    "int count;\n",
    "lwmqtt_unsubscribe_status_t statuses[", ll, "];\n",
    "lwmqtt_err_t err = lwmqtt_decode_unsuback(pkt, sizeof(pkt), &packet_id,",
    protlvl prot, ", ", ll, ", &count, statuses);\n",
    "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "EXPECT_EQ(packet_id, ", show pid, ");\n",
    "EXPECT_EQ(count, ", ll, ");\n",
    concatMap checkStatus (zip [0..] res)
    ]

    where
      checkStatus :: (Int,UnsubStatus) -> String
      checkStatus (qi,q) = "EXPECT_EQ(statuses[" <> show qi <> "], " <> b q <> ");\n"

      b UnsubSuccess                     = "LWMQTT_UNSUB_SUCCESS"
      b UnsubNoSubscriptionExisted       = "LWMQTT_UNSUB_NO_SUB_EXISTED"
      b UnsubUnspecifiedError            = "LWMQTT_UNSUB_UNSPECIFIED_ERROR"
      b UnsubImplementationSpecificError = "LWMQTT_UNSUB_IMPL_SPECIFIC_ERROR"
      b UnsubNotAuthorized               = "LWMQTT_UNSUB_NOT_AUTHORIZED"
      b UnsubTopicFilterInvalid          = "LWMQTT_UNSUB_TOPIC_FILTER_INVALID"
      b UnsubPacketIdentifierInUse       = "LWMQTT_UNSUB_PACKET_ID_IN_USE"


genDiscoTest :: ProtocolLevel -> Int -> DisconnectRequest -> String
genDiscoTest prot i p@(DisconnectRequest rsn props) = do
  genTestFunc "Disco" "Encode" prot i p $ mconcat [
    "uint8_t buf[sizeof(pkt)+10] = { 0 };\n",
    genProperties "props" props,
    "size_t len = 0;\n",
    "lwmqtt_err_t err = lwmqtt_encode_disconnect(buf, sizeof(buf), &len, ", protlvl prot, ", ", show (dr rsn), ", props);\n",
    "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
    "EXPECT_EQ(len, sizeof(pkt));\n",
    "EXPECT_ARRAY_EQ(pkt, buf, len);\n"
    ]

  where
    dr DiscoNormalDisconnection                 = 0x00
    dr DiscoDisconnectWithWill                  = 0x04
    dr DiscoUnspecifiedError                    = 0x80
    dr DiscoMalformedPacket                     = 0x81
    dr DiscoProtocolError                       = 0x82
    dr DiscoImplementationSpecificError         = 0x83
    dr DiscoNotAuthorized                       = 0x87
    dr DiscoServerBusy                          = 0x89
    dr DiscoServershuttingDown                  = 0x8B
    dr DiscoKeepAliveTimeout                    = 0x8D
    dr DiscoSessiontakenOver                    = 0x8e
    dr DiscoTopicFilterInvalid                  = 0x8f
    dr DiscoTopicNameInvalid                    = 0x90
    dr DiscoReceiveMaximumExceeded              = 0x93
    dr DiscoTopicAliasInvalid                   = 0x94
    dr DiscoPacketTooLarge                      = 0x95
    dr DiscoMessageRateTooHigh                  = 0x96
    dr DiscoQuotaExceeded                       = 0x97
    dr DiscoAdministrativeAction                = 0x98
    dr DiscoPayloadFormatInvalid                = 0x99
    dr DiscoRetainNotSupported                  = 0x9a
    dr DiscoQoSNotSupported                     = 0x9b
    dr DiscoUseAnotherServer                    = 0x9c
    dr DiscoServerMoved                         = 0x9d
    dr DiscoSharedSubscriptionsNotSupported     = 0x9e
    dr DiscoConnectionRateExceeded              = 0x9f
    dr DiscoMaximumConnectTime                  = 0xa0
    dr DiscoSubscriptionIdentifiersNotSupported = 0xa1
    dr DiscoWildcardSubscriptionsNotSupported   = 0xa2

genPubACKTest :: ProtocolLevel -> Int -> PubACKs -> String
genPubACKTest prot i pkt = enc <> dec

  where
    enc = tf (name pkt) "Encode" $ mconcat [
      "uint8_t buf[sizeof(pkt)+10];\n",
      genProperties "props" props,
      "size_t len;\n",
      "lwmqtt_err_t err = lwmqtt_encode_ack(buf, sizeof(buf), &len, ", protlvl prot, ", ", cname pkt, ", 0, ", show pid, ", ", show st, ", props);\n",
      "EXPECT_EQ(err, LWMQTT_SUCCESS);\n",
      "EXPECT_EQ(len, sizeof(pkt));\n",
      "EXPECT_ARRAY_EQ(pkt, buf, len);\n"
      ]
    dec = tf (name pkt) "Decode" $ mconcat [
      "uint16_t packet_id;\n",
      "uint8_t status;\n",
      "lwmqtt_serialized_properties_t props;\n",
      "bool dup;\n",
      "lwmqtt_err_t err = lwmqtt_decode_ack(pkt, sizeof(pkt), ", protlvl prot, ", ", cname pkt, ", &dup, &packet_id, &status, &props);\n",
      "EXPECT_EQ(err, ", exst st, ");\n",
      "EXPECT_EQ(packet_id, ", show pid, ");\n",
      "EXPECT_EQ(status, ", show st, ");\n"
      ]

    name = ("PubACK" <>) . head . words . show
    val (ACK x)  = toByteString prot x
    val (REC x)  = toByteString prot x
    val (REL x)  = toByteString prot x
    val (COMP x) = toByteString prot x

    pid = let (p,_,_) = parts pkt in p
    st = let (_,s,_) = parts pkt in s
    props = let (_,_,p) = parts pkt in p

    exst 0 = "LWMQTT_SUCCESS"
    exst _ = "LWMQTT_PUBACK_NACKED"

    parts (ACK (PubACK a b p))   = (a,b,p)
    parts (REC (PubREC a b p))   = (a,b,p)
    parts (REL (PubREL a b p))   = (a,b,p)
    parts (COMP (PubCOMP a b p)) = (a,b,p)

    cname (ACK _)  = "LWMQTT_PUBACK_PACKET"
    cname (REC _)  = "LWMQTT_PUBREC_PACKET"
    cname (REL _)  = "LWMQTT_PUBREL_PACKET"
    cname (COMP _) = "LWMQTT_PUBCOMP_PACKET"

    -- this is genTestFunc specialized to be more informative here.
    tf test tname body = let e = val pkt in
                                         mconcat [
      "// ", show pkt, "\n",
      "TEST(", test, shortprot prot, "QCTest, ", tname, show i <> ") {\n",
      "uint8_t pkt[] = {" <> hexa e <> "};\n",
      body, "\n",
      "}\n\n"
      ]


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

  pubax <- replicateM numTests $ generate arbitrary
  f genPubACKTest Protocol311 (v311ACKs <$> pubax)
  f genPubACKTest Protocol50 pubax

  conns <- replicateM numTests $ generate arbitrary
  f genConnectTest Protocol311 (userFix . v311ConnReq <$> conns)
  f genConnectTest Protocol50 (userFix <$> conns)

  subs <- replicateM numTests $ generate arbitrary
  f genSubTest Protocol311 (v311SubReq <$> subs)
  f genSubTest Protocol50 subs

  subax <- replicateM numTests $ generate arbitrary
  f genSubACKTest Protocol311 (v311SubACK <$> subax)
  f genSubACKTest Protocol50 subax

  unsubs <- replicateM numTests $ generate arbitrary
  f genUnsubTest Protocol311 (v311UnsubReq <$> unsubs)
  f genUnsubTest Protocol50 unsubs

  unsubax <- replicateM numTests $ generate arbitrary
  f genUnsubACKTest Protocol311 (v311UnsubACK <$> unsubax)
  f genUnsubACKTest Protocol50 unsubax

  discos <- replicateM numTests $ generate arbitrary
  f genDiscoTest Protocol311 (take 2 $ v311DiscoClean <$> discos) -- these are all the same
  f genDiscoTest Protocol50 discos

  where
    f :: (ProtocolLevel -> Int -> a -> String) -> ProtocolLevel -> [a] -> IO ()
    f g pl l = mapM_ putStrLn $ map (uncurry $ g pl) $ zip [1..] l

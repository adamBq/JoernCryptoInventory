// run_openssl_cbom_df_v2_4_1.sc
// OpenSSL + Libsodium CBOM + Impact with DF (v2.4.1+libsodium)
// Fixes (OpenSSL): AEAD IV/tag length parsing; CHACHA20-POLY1305 classification; mixed-mode candidate safety;
// TLS string/min/max/options capture; deduped candidate unions; RNG length arg fix; X25519 naming heuristics.
// Adds (Libsodium): AEAD (ChaCha20-Poly1305 / XChaCha20-Poly1305 / AES-256-GCM), Secretbox (XSalsa20-Poly1305),
// Box (X25519 + XSalsa20-Poly1305), KX (X25519), Sign (Ed25519), Hash (SHA2, BLAKE2b, SipHash), MAC (crypto_auth*),
// KDF/PWHASH (Argon2id), RNG (randombytes_*), Secretstream (XChaCha20-Poly1305). Robust to call.name/code mismatch.

// USAGE
// :load /abs/path/opensslibsodium_cbom.sc.sc
// workspace.reset
// importCode("/abs/path/<repo>")
// cryptoScan("/abs/path/<repo>", "/abs/path/cbom.cdx.json", ".*")

import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes
import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import java.util.UUID


var REPO    = ""
var OUTFILE = "cbom.cdx.json"

// -------- OpenSSL Regexes --------
// EVP creators
val CREATOR_RE  = "(?i)EVP_(EncryptInit_ex|DecryptInit_ex|CipherInit_ex|DigestSignInit|DigestVerifyInit|DigestInit_ex)"
// Factories
val CIPHER_RE   = "(?i)EVP_(aes_.*|des_.*|chacha20(_poly1305)?|sm4_.*)"
val DIGEST_RE   = "(?i)EVP_(sha(1|224|256|384|512)|shake(128|256)|blake2.*)"
val FETCH_RE    = "(?i)EVP_(CIPHER|MD|KDF|MAC)_fetch"

// CTRLS / signals
val CTRL_ANY_RE = "(?i)EVP_CIPHER_CTX_ctrl"
val CTRL_GCM_TAG_RE = "(?i).*EVP_CTRL_GCM_SET_TAG.*|.*EVP_CTRL_GCM_GET_TAG.*"
val CTRL_CCM_TAG_RE = "(?i).*EVP_CTRL_CCM_SET_TAG.*|.*EVP_CTRL_CCM_GET_TAG.*"
val CTRL_AEAD_IVLEN_RE = "(?i).*EVP_CTRL_AEAD_SET_IVLEN.*"

// Creation pass (conservative)
val RNG_RE      = "(?i)RAND_(priv_)?bytes"
val PBKDF2_RE   = "(?i)PKCS5_PBKDF2_HMAC"
val KDF_DERIVE  = "(?i)EVP_KDF_derive"
val PKEY_KEYGEN = "(?i)EVP_PKEY_(keygen|paramgen)(_init)?|RSA_generate_key_ex|EC_KEY_generate_key|DH_generate_key|DSA_generate_key"

// TLS (OpenSSL)
val TLS_CTX_NEW_RE       = "(?i)SSL_CTX_new"
val TLS_CLIENT_METH_RE   = "(?i)TLS_client_method"
val TLS_SERVER_METH_RE   = "(?i)TLS_server_method"
val TLS_SET_MIN_RE       = "(?i)SSL_CTX_set_min_proto_version"
val TLS_SET_MAX_RE       = "(?i)SSL_CTX_set_max_proto_version"
val TLS_SET_OPTS_RE      = "(?i)SSL_CTX_set_options"
val TLS_SET_SUITES_RE    = "(?i)SSL_CTX_set_ciphersuites"
val TLS_SET_LIST_RE      = "(?i)SSL_CTX_set_cipher_list"
val TLS_SET_VERIFY_RE    = "(?i)SSL_CTX_set_verify"
val TLS_CA_PATHS_RE      = "(?i)SSL_CTX_load_verify_locations"
val TLS_USE_CERT_RE      = "(?i)SSL_CTX_use_certificate_file"
val TLS_USE_KEY_RE       = "(?i)SSL_CTX_use_PrivateKey_file"
val TLS_CONNECT_RE       = "(?i)SSL_connect"
val TLS_ACCEPT_RE        = "(?i)SSL_accept"

// --- PQC Regexes (OpenSSL/Provider world) ---
val PQC_NAME_RE = "(?i)(ML[-_]?KEM|ML[-_]?DSA|SLH[-_]?DSA|FN[-_]?DSA|KYBER|DILITHIUM|SPHINCS\\+?|FALCON)"
val OQS_PROVIDER_HINT_RE = "(?i)(oqs|oqsprovider)"
val PQC_PKEY_ID_RE = "(?i)EVP_PKEY_(MLKEM|ML_DSA|SLH_DSA|FN_DSA|KYBER|DILITHIUM|SPHINCS|FALCON)"

// -------- Libsodium Regexes --------
// AEAD
val SODIUM_AEAD_RE = "(?i)crypto_aead_(chacha20poly1305_ietf|xchacha20poly1305_ietf|aes256gcm)_(encrypt|decrypt)"
// Secretbox (XSalsa20-Poly1305)
val SODIUM_SECRETBOX_RE = "(?i)crypto_secretbox(_easy|_open_easy|_detached|_open_detached)"
// Box (X25519 + XSalsa20-Poly1305)
val SODIUM_BOX_RE = "(?i)crypto_box_(easy|open_easy|detached|open_detached|seal|open_seal|beforenm|easy_afternm)"
// KX / ECDH
val SODIUM_KX_RE = "(?i)crypto_kx_(client_session_keys|server_session_keys)"
val SODIUM_SCALARMULT_RE = "(?i)crypto_scalarmult(_base)?"
// Signatures (Ed25519)
val SODIUM_SIGN_RE = "(?i)crypto_sign(_ed25519)?_(init|update|final|detached|verify_detached|open|keypair)"
// Hashes
val SODIUM_HASH_RE = "(?i)crypto_hash_(sha256|sha512)"
val SODIUM_GHASH_RE = "(?i)crypto_generichash(_init|_update|_final)?"
val SODIUM_SHORT_HASH_RE = "(?i)crypto_shorthash(_siphash24|_siphashx24)?"
// MAC / Auth (include plain crypto_auth)
val SODIUM_AUTH_RE = "(?i)crypto_auth(_hmacsha256|_hmacsha512)?(_(init|update|final|verify))?"
// PWHASH / KDF
val SODIUM_PWHASH_RE = "(?i)crypto_pwhash(_argon2id)?"
val SODIUM_KDF_RE = "(?i)crypto_kdf_derive_from_key"
// RNG
val SODIUM_RANDOM_RE = "(?i)randombytes_(buf|buf_deterministic|uniform)"
// Secretstream (XChaCha20-Poly1305)
val SODIUM_SECRETSTREAM_RE = "(?i)crypto_secretstream_xchacha20poly1305_(init_push|init_pull|push|pull|rekey)"

// -------- Models --------
case class Evidence(file: String, function: String, line: Int, snippet: String)
case class AssetKey(file: String, operation: String, algorithm: String, mode: String, keySize: String)
case class Asset(
  key: AssetKey,
  provider: String,
  primitive: String,              // cipher | aead | signature | hash | kdf | rng | params | mac | tls | kx | asym-enc
  pqCategory: String,             // public-key | symmetric | hash | unknown
  pqVulnerability: String,        // quantum-vulnerable | symmetric-safe | legacy-insecure | unknown
  ivSource: Option[String],
  properties: Map[String,String],
  weaknesses: List[String],
  evidence: List[Evidence]
)
case class ImpactEdge(srcFile: String, dstFile: String, caller: String, callee: String, line: Int)

// -------- Utils --------
def q(s: String) =
  Option(s).getOrElse("")
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\r", "\\r")
    .replace("\t", "\\t")
def prop(name: String, value: String) = s"""{"name":"${q(name)}","value":"${q(value)}"}"""
def sha256Hex(bytes: Array[Byte]): String = {
  val md = MessageDigest.getInstance("SHA-256"); md.digest(bytes).map("%02x".format(_)).mkString
}
def stableId(s: String): String = {
  val md = MessageDigest.getInstance("SHA-1"); md.digest(s.getBytes("UTF-8")).map("%02x".format(_)).mkString
}
def stripQuotes(s: String): String = q(s).replaceAll("""^"+|"+$""", "")

// Robust Libsodium helper: match by name OR code (handles Joern normalization)
def callsByNameOrCode(re: String, scopeRegex: String) = {
  val byName = cpg.call.where(_.file.name(scopeRegex)).name(re).l
  val byCode = cpg.call.where(_.file.name(scopeRegex)).code(re).l
  (byName ++ byCode).distinct
}

// -------- Classification --------
def opFromName(n: String): String = {
  val l = n.toLowerCase
  if (l.contains("encryptinit") || l.contains("cipherinit")) "encrypt"
  else if (l.contains("decryptinit")) "decrypt"
  else if (l.contains("digestsigninit")) "sign"
  else if (l.contains("digestverifyinit")) "verify"
  else if (l.contains("digestinit")) "hash"
  else ""
}

def parseAlgMode(s: String): (String,String,String) = {
  val x = s.toLowerCase
  val alg =
    if (x.matches(s".*${PQC_NAME_RE}.*")) {
      if (x.contains("ml-kem") || x.contains("kyber")) "ML-KEM"
      else if (x.contains("ml-dsa") || x.contains("dilithium")) "ML-DSA"
      else if (x.contains("slh-dsa") || x.contains("sphincs")) "SLH-DSA"
      else if (x.contains("fn-dsa") || x.contains("falcon")) "FN-DSA"
      else "PQC"
    } else if (x.contains("rsa")) "RSA"
    else if (x.contains("ecdsa")) "ECDSA"
    else if (x.contains("ed25519")) "Ed25519"
    else if (x.contains("x25519")) "X25519"
    else if (x.contains("aes")) "AES"
    else if (x.contains("des3") || x.contains("3des") || x.contains("des_ede")) "3DES"
    else if (x.contains("des")) "DES"
    else if (x.contains("sm4")) "SM4"
    else if (x.contains("rc4")) "RC4"
    else if (x.contains("md5")) "MD5"
    else if (x.contains("sha1")) "SHA1"
    else if (x.contains("sha256")) "SHA256"
    else if (x.contains("sha384")) "SHA384"
    else if (x.contains("sha512")) "SHA512"
    else if (x.contains("shake128")) "SHAKE128"
    else if (x.contains("shake256")) "SHAKE256"
    else if (x.contains("chacha20") || x.contains("poly1305")) "CHACHA20-POLY1305"
    else if (x.contains("blake2") || x.contains("generichash")) "BLAKE2b"
    else if (x.contains("siphash")) "SIPHASH"
    else if (x.contains("argon2id") || x.contains("pwhash")) "ARGON2ID"
    else "UNKNOWN"

  val mode =
    if (alg == "CHACHA20-POLY1305") "AEAD"
    else if (x.contains("gcm")) "GCM"
    else if (x.contains("ccm")) "CCM"
    else if (x.contains("cbc")) "CBC"
    else if (x.contains("ecb")) "ECB"
    else if (x.contains("ctr")) "CTR"
    else if (alg.startsWith("SHA") || alg.startsWith("SHAK") || alg=="MD5" || alg=="BLAKE2b" || alg=="SIPHASH") "HASH"
    else if (alg=="RSA" || alg=="ECDSA" || alg=="Ed25519" || alg=="ML-DSA" || alg=="SLH-DSA" || alg=="FN-DSA") "SIGN"
    else if (alg=="X25519" || alg=="ML-KEM") "KEM"
    else if (alg=="ARGON2ID") "KDF"
    else ""

  val ksRaw = "(\\d{3,4})".r.findFirstIn(x).getOrElse("")
  val ks    = if (alg == "CHACHA20-POLY1305") "" else ksRaw
  (alg, mode, ks)
}

def primitiveFor(op: String, alg: String, mode: String): String =
  if (alg == "ML-KEM" || mode == "KEM") "kem"
  else if (alg == "CHACHA20-POLY1305" || mode == "GCM" || mode == "CCM") "aead"
  else if (op=="sign" || op=="verify" || alg=="RSA" || alg=="ECDSA" || alg=="Ed25519" || alg=="ML-DSA" || alg=="SLH-DSA" || alg=="FN-DSA") "signature"
  else if (alg.startsWith("SHA") || alg=="MD5" || alg=="BLAKE2b" || alg=="SIPHASH") "hash"
  else if (alg=="AES" || alg=="DES" || alg=="3DES" || alg=="SM4" || alg=="RC4" || mode=="CBC" || mode=="ECB" || mode=="CTR") "cipher"
  else if (alg=="X25519") "kx"
  else if (alg=="ARGON2ID") "kdf"
  else if (op=="hash") "hash"
  else ""

def pqMeta(alg: String, op: String): (String,String) = {
  // PQ-safe (OpenSSL PQC families)
  if (alg=="ML-KEM" || alg=="ML-DSA" || alg=="SLH-DSA" || alg=="FN-DSA")
    ("public-key","post-quantum-safe")
  // Classical public key
  else if (op=="sign" || op=="verify" || alg=="RSA" || alg=="ECDSA" || alg=="Ed25519" || alg=="X25519")
    ("public-key","quantum-vulnerable")
  // Hashes (neutral for PQ; weakness handled separately)
  else if (alg.startsWith("SHA") || alg=="MD5" || alg=="BLAKE2b" || alg=="SIPHASH")
    ("hash","unknown")
  // Symmetric
  else if (alg=="AES" || alg=="SM4" || alg=="CHACHA20-POLY1305")
    ("symmetric","symmetric-safe")
  else if (alg=="DES" || alg=="3DES" || alg=="RC4")
    ("symmetric","legacy-insecure")
  else if (alg=="ARGON2ID")
    ("unknown","unknown")
  else
    ("unknown","unknown")
}

def weaknessTags(code: String, name: String): List[String] = {
  val l = (Option(code).getOrElse("") + " " + Option(name).getOrElse("")).toLowerCase
  val tags = scala.collection.mutable.ListBuffer[String]()
  if (l.contains("des_") || (l.contains(" des") && !l.contains("3des"))) tags += "DES-legacy"
  if (l.contains("des3") || l.contains("3des") || l.contains("des_ede")) tags += "3DES-legacy"
  if (l.contains("rc4")) tags += "RC4-legacy"
  if (l.contains("md5")) tags += "MD5-weak"
  if (l.contains("sha1")) tags += "SHA1-weak"
  if (l.contains("ecb")) tags += "ECB-insecure"
  if (l.contains("cbc")) tags += "CBC-check-iv-source"
  tags.toList
}

// -------- Data-flow helpers --------
def dfAvailable(): Boolean =
  try { cpg.call.argument(1).reachableBy(cpg.literal).take(1).nonEmpty; true } catch { case _: Throwable => false }

def resolveFactories(arg: nodes.Expression, re: String): Set[String] = {
  val direct = Option(arg.code).toList
  val dfSyms =
    try arg.reachableBy(cpg.call.name(re)).map(_.name).l
    catch { case _: Throwable => Nil }
  (direct ++ dfSyms).filter(_.matches(re)).map(_.replace("()","")).toSet
}

def resolveProvider(m: nodes.Method): Option[String] = {
  val calls = m.call
  val fetch = calls.name(FETCH_RE).code.l.mkString("\n").toLowerCase
  if (fetch.contains("fips")) Some("fips")
  else if (fetch.matches(s".*${OQS_PROVIDER_HINT_RE}.*")) Some("oqs")
  else if (fetch.contains("default")) Some("default")
  else if (fetch.nonEmpty) Some("provider")
  else None
}

// Key type/origin for sign/verify (OpenSSL EVP)
def resolveKeyTypeAndOrigin(arg: nodes.Expression): (String, Map[String,String]) = {
  val dfText = try arg.reachableBy(cpg.call).code.l.mkString("\n").toLowerCase catch { case _:Throwable => "" }
  val text = (Option(arg.code).getOrElse("").toLowerCase + "\n" + dfText)
  val fromPem = text.contains("pem_read") || text.contains("pem_read_bio") || text.contains("d2i_")

  val isRSA = text.contains("rsa_") || text.contains("evp_pkey_assign_rsa") || text.contains("rsa_generate_key_ex") || text.contains("evp_pkey_set1_rsa")
  val isEC  = text.contains("ec_")  || text.contains("evp_pkey_assign_ec_key") || text.contains("ec_key_new_by_curve_name") || text.contains("evp_pkey_set1_ec_key")
  val isEd  = text.contains("evp_pkey_ed25519") || text.contains("ed25519")
  val isX   = text.contains("evp_pkey_x25519")  || text.contains("x25519")

  val hasPQCName = text.matches(s".*${PQC_NAME_RE}.*") || text.matches(s".*${PQC_PKEY_ID_RE}.*") || text.matches(s".*${OQS_PROVIDER_HINT_RE}.*")
  val pqAlg =
    if (hasPQCName && (text.contains("kem") || text.contains("ml-kem") || text.contains("kyber"))) "ML-KEM"
    else if (hasPQCName && (text.contains("ml-dsa") || text.contains("dilithium"))) "ML-DSA"
    else if (hasPQCName && (text.contains("slh-dsa") || text.contains("sphincs"))) "SLH-DSA"
    else if (hasPQCName && (text.contains("fn-dsa") || text.contains("falcon"))) "FN-DSA"
    else ""

  val curve =
    if (text.contains("nid_x9_62_prime256v1") || text.contains("prime256v1")) "P-256"
    else if (text.contains("secp384r1")) "P-384"
    else if (text.contains("secp521r1")) "P-521"
    else ""

  if (pqAlg.nonEmpty) (pqAlg, Map("key.origin" -> (if (fromPem) "pem" else "local")))
  else if (isEd) ("Ed25519", Map("key.origin"->(if (fromPem) "pem" else "local")))
  else if (isX) ("X25519", Map("key.origin"->(if (fromPem) "pem" else "local")))
  else if (isRSA) ("RSA", Map("key.origin"->(if (fromPem) "pem" else "local")))
  else if (isEC) ("ECDSA", Map("key.origin"->(if (fromPem) "pem" else "local")) ++ (if (curve.nonEmpty) Map("key.curve"->curve) else Map()))
  else if (fromPem) ("UNKNOWN", Map("key.origin"->"pem"))
  else ("UNKNOWN", Map.empty)
}

// IV/nonce classification (OpenSSL-style IV; Libsodium infers by family)
def classifyIvSource(arg: nodes.Expression): String = {
  val lc = Option(arg.code).getOrElse("").toLowerCase
  val df = try arg.reachableBy(cpg.call, cpg.literal, cpg.identifier).code.l.map(_.toLowerCase).mkString("\n")
           catch { case _: Throwable => "" }
  val text = lc + "\n" + df
  if (text.contains("rand_bytes(")) "rand"
  else if (text.contains("memset(") && text.contains(",0,")) "memset-zero"
  else if (text.contains("bzero(")) "bzero"
  else if (text.contains("calloc(")) "calloc-zero"
  else if (lc == "null" || lc == "0") "null"
  else if (text.contains("{0}")) "zero-literal"
  else "unknown"
}

// AEAD metadata extraction (OpenSSL)
def aeadIvLenIn(m: nodes.Method): Option[String] =
  m.call.name(CTRL_ANY_RE)
    .where(_.argument(2).code(CTRL_AEAD_IVLEN_RE))
    .argument(3).code.headOption.map(_.trim).filter(_.nonEmpty)

def aeadTagLenIn(m: nodes.Method): Option[String] = {
  val gcm = m.call.name(CTRL_ANY_RE).where(_.argument(2).code(CTRL_GCM_TAG_RE)).argument(3).code.headOption
  val ccm = m.call.name(CTRL_ANY_RE).where(_.argument(2).code(CTRL_CCM_TAG_RE)).argument(3).code.headOption
  (gcm.orElse(ccm)).map(_.trim).filter(_.nonEmpty)
}

// AAD presence: detect Update calls where dst buffer is NULL
def hasAadIn(m: nodes.Method): Boolean = {
  m.call.name("(?i)EVP_(Encrypt|Decrypt)Update").l.exists { c =>
    val arg2 = Option(c.argument(2).code).getOrElse("")
    arg2 == "NULL" || arg2 == "0"
  }
}

// -------- TLS gather (OpenSSL) --------
case class TlsInfo(role: String, minV: Option[String], maxV: Option[String], opts: List[String], suites: Option[String], list: Option[String], verifyMode: Option[String], verifySources: Option[String], certPath: Option[String], keyPath: Option[String])
def gatherTls(m: nodes.Method): Option[(Asset, Evidence)] = {
  val file = m.file.name.headOption.getOrElse(""); if (file.isEmpty) return None
  val role =
    if (m.call.name(TLS_CONNECT_RE).nonEmpty) "client"
    else if (m.call.name(TLS_ACCEPT_RE).nonEmpty) "server"
    else {
      val ctxNew = m.call.name(TLS_CTX_NEW_RE).code.l.mkString("\n").toLowerCase
      if (ctxNew.contains("tls_client_method")) "client"
      else if (ctxNew.contains("tls_server_method")) "server"
      else "unknown"
    }

  def strArg(c: nodes.Call, idx: Int): Option[String] = Option(c.argument(idx).code).map(_.trim).filter(_.nonEmpty).map(s => stripQuotes(s))

  val minV = m.call.name(TLS_SET_MIN_RE).argument(2).code.headOption
  val maxV = m.call.name(TLS_SET_MAX_RE).argument(2).code.headOption

  val opts  = m.call.name(TLS_SET_OPTS_RE).l.flatMap { c =>
    val raw = c.code
    "(SSL_OP_[A-Z0-9_]+)".r.findAllMatchIn(raw).map(_.group(1)).toList
  }.distinct.sorted

  val suites = m.call.name(TLS_SET_SUITES_RE).l.flatMap(c => strArg(c,2)).headOption
  val list   = m.call.name(TLS_SET_LIST_RE).l.flatMap(c => strArg(c,2)).headOption

  val verifyMode = m.call.name(TLS_SET_VERIFY_RE).argument(2).code.headOption
  val verifySources =
    if (m.call.name(TLS_CA_PATHS_RE).nonEmpty) Some("custom|default") else None

  val certPath = m.call.name(TLS_USE_CERT_RE).l.flatMap(c => strArg(c,2)).headOption
  val keyPath  = m.call.name(TLS_USE_KEY_RE).l.flatMap(c => strArg(c,2)).headOption

  val props = Map(
    "tls.min" -> minV.getOrElse(""),
    "tls.max" -> maxV.getOrElse(""),
    "tls.options" -> (if (opts.nonEmpty) opts.mkString(" ") else ""),
    "tls.ciphersuites" -> suites.getOrElse(""),
    "tls.cipher_list" -> list.getOrElse(""),
    "tls.verify_mode" -> verifyMode.getOrElse(""),
    "tls.verify_sources" -> verifySources.getOrElse(""),
    "tls.cert.path" -> certPath.getOrElse(""),
    "tls.key.path" -> keyPath.getOrElse("")
  )

  val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), m.call.name(TLS_CTX_NEW_RE).code.headOption.getOrElse("SSL_CTX_new(...)"))
  val asset = Asset(
    key = AssetKey(file, "tls", "TLS", "", ""),
    provider = "OpenSSL",
    primitive = "tls",
    pqCategory = pqMeta("TLS","tls")._1,
    pqVulnerability = pqMeta("TLS","tls")._2,
    ivSource = None,
    properties = Map("role" -> role) ++ props,
    weaknesses = Nil,
    evidence = List(ev)
  )
  Some(asset, ev)
}

// -------- EVP scan (OpenSSL) --------
def scanEVPAssets(scopeRegex: String): List[Asset] = {
  val creators = cpg.call.where(_.file.name(scopeRegex)).name(CREATOR_RE).l
  val withExtras = creators.map { c =>
    val file = c.file.name.headOption.getOrElse("")
    val func = c.method.fullName
    val line = c.lineNumber.getOrElse(0)
    val op   = opFromName(c.name)

    val typeArg = c.argument(2)
    val cipherSyms = resolveFactories(typeArg, CIPHER_RE)
    val digestArg = if (c.name.matches("(?i).*DigestInit_ex")) c.argument(2) else c.argument(3)
    val digestSyms = resolveFactories(digestArg, DIGEST_RE)

    val pkeyArg = if (op=="sign" || op=="verify") c.argument(5) else null
    val (keyKind, keyExtra) =
      if (op=="sign" || op=="verify") resolveKeyTypeAndOrigin(pkeyArg) else ("", Map.empty[String,String])

    val algTokens = (cipherSyms ++ digestSyms + Option(typeArg.code).getOrElse("")).mkString(" ")
    var (alg, mode, ks) = parseAlgMode(algTokens)

    var prim = primitiveFor(op, alg, mode)
    var (pqCat, pqVuln) = pqMeta(alg, op)

    var props = Map[String,String]() ++ keyExtra
    if ((op=="sign" || op=="verify") && keyKind.nonEmpty) {
      alg = keyKind
      mode = if (alg=="ML-DSA" || alg=="SLH-DSA" || alg=="FN-DSA") "SIGN" else ""
      prim = "signature"
      val (pc, pv) = pqMeta(alg, op); pqCat = pc; pqVuln = pv
    }

    if (digestSyms.nonEmpty) {
      val ds = digestSyms.toList.map(_.toUpperCase.replace("EVP_","")).distinct.sorted.mkString(" | ")
      props += ("digest.variants" -> ds)
    }
    val candidates =
      cipherSyms.toList.map(_.toUpperCase.replace("EVP_","")).distinct.sorted
    if (candidates.nonEmpty) props += ("candidates" -> candidates.mkString(" | "))

    val hasCBC = candidates.exists(_.contains("CBC"))
    val hasAEAD = candidates.exists(s => s.contains("GCM") || s.contains("CCM") || s.contains("POLY1305"))
    if (hasCBC && hasAEAD) prim = "unknown"

    val ivSrc =
      if (op=="encrypt" || op=="decrypt") {
        val ivArgOpt = c.argumentOption(5).orElse(c.argumentOption(4))
        ivArgOpt.map(classifyIvSource)
      } else None

    val weak = weaknessTags(c.code, c.name)
    val ctx  = c.method
    aeadTagLenIn(ctx).foreach(t => props += ("aead.tagLen" -> t))
    aeadIvLenIn(ctx).foreach(v => props += ("aead.ivLen" -> v))
    if (hasAadIn(ctx)) props += ("aead.aad" -> "present")
    resolveProvider(ctx).foreach(p => props += ("provider" -> p))

    val evi = Evidence(file, func, line, c.code)
    Asset(
      key = AssetKey(file, op, alg, mode, ks),
      provider = props.getOrElse("provider", "OpenSSL"),
      primitive = prim,
      pqCategory = pqCat,
      pqVulnerability = pqVuln,
      ivSource = ivSrc.orElse(Some("")), // always present (maybe "")
      properties = props,
      weaknesses = weak,
      evidence = List(evi)
    )
  }

  // Add method-local evidence and merge duplicates
  val enriched = withExtras.groupBy(_.key.file).flatMap { case (_, list) =>
    val mnames = list.map(_.evidence.head.function).toSet
    val mobs = cpg.method.fullNameExact(mnames.toSeq*).l
    val extra  = mobs.flatMap(_.call.l)
    list.map { a =>
      val moreEv = extra.filter { ec =>
        val n = ec.name
        n.matches(CIPHER_RE) || n.matches(DIGEST_RE) ||
        n.matches("(?i)EVP_.*(Update|Final).*") ||
        n.matches(CTRL_ANY_RE) || n.matches(FETCH_RE)
      }.map(ec => Evidence(a.key.file, ec.method.fullName, ec.lineNumber.getOrElse(0), ec.code))
      a.copy(evidence = (a.evidence ++ moreEv).distinct)
    }
  }.toList

  // Merge by AssetKey
  enriched.groupBy(_.key).map { case (k, xs) =>
    val one = xs.head
    val props = xs.map(_.properties).foldLeft(Map.empty[String,String])(_ ++ _)
    one.copy(
      properties = props,
      evidence = xs.flatMap(_.evidence).distinct.sortBy(e => (e.file, e.function, e.line)),
      weaknesses = xs.flatMap(_.weaknesses).distinct
    )
  }.toList
}

// ---- Optional creation pass (OpenSSL RNG/KDF/Keygen, MACs, PKEY derive/asym-enc) ----
def scanCreationAssets(scopeRegex: String): List[Asset] = {
  val calls = cpg.call.where(_.file.name(scopeRegex))

  // RNG
  val rng = calls.name(RNG_RE).l.map { c =>
    val file = c.file.name.headOption.getOrElse("")
    val evi = Evidence(file, c.method.fullName, c.lineNumber.getOrElse(0), c.code)
    val len = Option(c.argument(2).code).getOrElse("")
    Asset(AssetKey(file,"derive","RNG","",len),
      "OpenSSL","rng","unknown","unknown",None,
      Map("secret_length"->len),Nil,List(evi))
  }

  val pbkdf = calls.name(PBKDF2_RE).l.map { c =>
    val file = c.file.name.headOption.getOrElse("")
    val evi  = Evidence(file, c.method.fullName, c.lineNumber.getOrElse(0), c.code)
    val keylen = Option(c.argument(7).code).getOrElse("")
    val iter = Option(c.argument(5).code).getOrElse("")
    val hash = Option(c.argument(6).code).getOrElse("").replace("EVP_","").toUpperCase
    Asset(AssetKey(file,"derive","PBKDF2","",keylen),
      "OpenSSL","kdf","unknown","unknown",None,
      Map("iterations"->iter,"hash"->hash,"key_length"->keylen),
      Nil,List(evi))
  }

  val kdfd = calls.name(KDF_DERIVE).l.map { c =>
    val file = c.file.name.headOption.getOrElse("")
    val evi = Evidence(file, c.method.fullName, c.lineNumber.getOrElse(0), c.code)
    val outlen = Option(c.argument(2).code).getOrElse("")
    Asset(AssetKey(file,"derive","KDF","",outlen),
      "OpenSSL","kdf","unknown","unknown",None,
      Map("key_length"->outlen),Nil,List(evi))
  }

  // EVP_PKEY derive (kx), try to identify X25519
  val pkeyDerive = calls.name("(?i)EVP_PKEY_derive(_init)?").l.groupBy(_.method.fullName).toList.flatMap { case (_, lst) =>
    val m = lst.head.method
    val file = m.file.name.headOption.getOrElse("")
    val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), lst.head.code)
    val mtxt = (m.call.code.l ++ m.parameter.code.l ++ m.local.name.l).mkString("\n").toLowerCase
    val alg =
      if (mtxt.contains("x25519")) "X25519"
      else "PKEY"
    val prim = "kx"
    Some(Asset(AssetKey(file,"derive",alg,"",""), "OpenSSL", prim, "public-key", "quantum-vulnerable", None, Map.empty, Nil, List(ev)))
  }

  // Asymmetric encrypt/decrypt via EVP_PKEY_* with RSA padding hints
  val pkeyEnc = calls.name("(?i)EVP_PKEY_encrypt_init|EVP_PKEY_encrypt|EVP_PKEY_decrypt_init|EVP_PKEY_decrypt|EVP_PKEY_CTX_set_rsa_padding|EVP_PKEY_CTX_set_rsa_oaep_md|EVP_PKEY_CTX_set_rsa_mgf1_md").l
    .groupBy(_.method.fullName).toList.map { case (_, list) =>
      val m = list.head.method
      val file = m.file.name.headOption.getOrElse("")
      val codeBlob = list.map(_.code).mkString("\n").toLowerCase
      val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), list.head.code)
      val isEnc = codeBlob.contains("evp_pkey_encrypt")
      val isDec = codeBlob.contains("evp_pkey_decrypt")
      val op = if (isEnc) "encrypt" else if (isDec) "decrypt" else "encrypt"
      val pad =
        if (codeBlob.contains("oaep")) "OAEP"
        else if (codeBlob.contains("pkcs1_padding")) "PKCS1-v1_5"
        else ""
      val oaepHash =
        if (codeBlob.contains("evp_sha256")) "SHA256"
        else if (codeBlob.contains("evp_sha1")) "SHA1"
        else ""
      val mgfHash = oaepHash
      val props = Map(
        "rsa.padding" -> pad,
        "rsa.oaep.hash" -> (if (pad=="OAEP") oaepHash else ""),
        "rsa.mgf1.hash" -> (if (pad=="OAEP") mgfHash else "")
      )
      Asset(AssetKey(file, op, "RSA", "", ""), "OpenSSL", "asym-enc", "public-key", "quantum-vulnerable", None, props, Nil, List(ev))
    }

  // MACs (classic + EVP_MAC)
  val hmac = calls.name("(?i)HMAC_(Init_ex|Update|Final)").l.groupBy(_.method.fullName).toList.map { case (_, list) =>
    val m = list.head.method; val file = m.file.name.headOption.getOrElse("")
    val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), list.head.code)
    val text = list.map(_.code).mkString("\n")
    val digest =
      if (text.contains("EVP_sha256")) "SHA256"
      else if (text.contains("EVP_sha1")) "SHA1"
      else ""
    Asset(AssetKey(file,"mac","HMAC","",""), "OpenSSL","mac","symmetric","symmetric-safe",None,
      Map("digest"->digest), Nil, List(ev))
  }

  val cmac = calls.name("(?i)CMAC_(Init|Update|Final)").l.groupBy(_.method.fullName).toList.map { case (_, list) =>
    val m = list.head.method; val file = m.file.name.headOption.getOrElse("")
    val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), list.head.code)
    val cands = "(EVP_[a-z0-9_]+)".r.findAllIn(list.map(_.code).mkString("\n")).toList
      .filter(_.toUpperCase.contains("EVP_AES_")).map(_.toUpperCase.replace("EVP_","")).distinct.sorted
    val props = if (cands.nonEmpty) Map("cmac.cipher"->cands.mkString(" | ")) else Map.empty[String,String]
    Asset(AssetKey(file,"mac","CMAC","",""), "OpenSSL","mac","symmetric","symmetric-safe",None, props, Nil, List(ev))
  }

  val evpMac = calls.name("(?i)EVP_MAC_(fetch|init|update|final)").l.groupBy(_.method.fullName).toList.map { case (_, list) =>
    val m = list.head.method; val file = m.file.name.headOption.getOrElse("")
    val ev = Evidence(file, m.fullName, m.lineNumber.getOrElse(0), list.head.code)
    val text = list.map(_.code).mkString("\n").toLowerCase
    val mtype =
      if (text.contains("\"hmac\"")) "HMAC"
      else if (text.contains("\"cmac\"")) "CMAC"
      else ""
    Asset(AssetKey(file,"mac","EVP_MAC","",""), "OpenSSL","mac","symmetric","symmetric-safe",None,
      Map("mac.type"->mtype), Nil, List(ev))
  }

  rng ++ pbkdf ++ kdfd ++ pkeyDerive ++ pkeyEnc ++ hmac ++ cmac ++ evpMac
}

// -------- Libsodium scan --------
def sodiumIvLenByFamily(nameOrCode: String): Option[String] = {
  val x = nameOrCode.toLowerCase
  if (x.contains("xchacha20poly1305")) Some("24")
  else if (x.contains("chacha20poly1305_ietf")) Some("12")
  else if (x.contains("secretbox")) Some("24") // XSalsa20-Poly1305 nonce
  else if (x.contains("aes256gcm")) Some("12")
  else if (x.contains("secretstream_xchacha20poly1305")) Some("24")
  else None
}

def sodiumAlgAndPrim(nameOrCode: String, defaultOp: String): (String,String,String,String) = {
  val x = nameOrCode.toLowerCase
  if (x.contains("xchacha20poly1305")) ("CHACHA20-POLY1305","aead","AEAD","symmetric-safe")
  else if (x.contains("chacha20poly1305_ietf")) ("CHACHA20-POLY1305","aead","AEAD","symmetric-safe")
  else if (x.contains("aes256gcm")) ("AES","aead","GCM","symmetric-safe")
  else if (x.contains("secretbox")) ("CHACHA20-POLY1305","aead","AEAD","symmetric-safe") // XSalsa20-Poly1305 variant
  else if (x.contains("crypto_box_")) ("X25519","kx","", "quantum-vulnerable")
  else if (x.contains("crypto_kx_") || x.contains("crypto_scalarmult")) ("X25519","kx","", "quantum-vulnerable")
  else if (x.contains("crypto_sign")) ("Ed25519","signature","SIGN","quantum-vulnerable")
  else if (x.contains("crypto_hash_sha256")) ("SHA256","hash","HASH","unknown")
  else if (x.contains("crypto_hash_sha512")) ("SHA512","hash","HASH","unknown")
  else if (x.contains("crypto_generichash")) ("BLAKE2b","hash","HASH","unknown")
  else if (x.contains("crypto_shorthash")) ("SIPHASH","hash","HASH","unknown")
  else if (x.contains("crypto_auth")) ("HMAC","mac","","symmetric-safe")
  else if (x.contains("crypto_pwhash")) ("ARGON2ID","kdf","KDF","unknown")
  else if (x.contains("crypto_kdf_derive_from_key")) ("KDF","kdf","KDF","unknown")
  else if (x.contains("randombytes_")) ("RNG","rng","","unknown")
  else if (x.contains("secretstream_xchacha20poly1305")) ("CHACHA20-POLY1305","aead","AEAD","symmetric-safe")
  else ("UNKNOWN","", "", "unknown")
}

def scanSodiumAssets(scopeRegex: String): List[Asset] = {
  val all = List(
    SODIUM_AEAD_RE, SODIUM_SECRETBOX_RE, SODIUM_BOX_RE, SODIUM_KX_RE, SODIUM_SCALARMULT_RE,
    SODIUM_SIGN_RE, SODIUM_HASH_RE, SODIUM_GHASH_RE, SODIUM_SHORT_HASH_RE,
    SODIUM_AUTH_RE, SODIUM_PWHASH_RE, SODIUM_KDF_RE, SODIUM_RANDOM_RE, SODIUM_SECRETSTREAM_RE
  )

  val sodiumCalls = all.flatMap(re => callsByNameOrCode(re, scopeRegex)).distinct

  // Map calls to assets (group by method to reduce duplicates where appropriate)
  val groupedByMethod = sodiumCalls.groupBy(_.method.fullName).toList

  val assets = groupedByMethod.flatMap { case (_, calls) =>
    val m  = calls.head.method
    val file = m.file.name.headOption.getOrElse("")
    calls.map { c =>
      val code = Option(c.code).getOrElse("").toLowerCase
      val op =
        if (code.contains("_encrypt(") || code.contains("push(") || code.contains("seal(") || code.contains("easy(")) "encrypt"
        else if (code.contains("_decrypt(") || code.contains("pull(") || code.contains("open_")) "decrypt"
        else if (code.contains("verify") || code.contains("_open(")) "verify"
        else if (code.contains("keypair")) "sign"
        else if (code.contains("client_session_keys") || code.contains("server_session_keys") || code.contains("scalarmult")) "derive"
        else if (code.contains("pwhash") || code.contains("derive_from_key")) "derive"
        else if (code.contains("randombytes_")) "derive"
        else if (code.contains("sign_") && (code.contains("detached") || code.contains("final"))) "sign"
        else "encrypt"

      val (alg, prim, mode, pqV) = sodiumAlgAndPrim(code, op)
      val (pqCat, pqVuln) =
        if (alg == "X25519" || alg == "Ed25519") ("public-key", pqV)
        else if (alg == "CHACHA20-POLY1305" || alg == "AES") ("symmetric", pqV)
        else if (alg.startsWith("SHA") || alg == "BLAKE2b" || alg == "SIPHASH") ("hash", "unknown")
        else if (alg == "ARGON2ID" || alg == "KDF") ("unknown", "unknown")
        else if (alg == "RNG") ("unknown", "unknown")
        else ("unknown", "unknown")

      val ivLen = sodiumIvLenByFamily(code)
      val propsBase = scala.collection.mutable.Map[String,String]("provider" -> "Libsodium")
      ivLen.foreach(v => propsBase += ("aead.ivLen" -> v))
      if (code.contains("aad") || code.contains("ad,")) propsBase += ("aead.aad" -> "present")

      val evi = Evidence(file, m.fullName, c.lineNumber.getOrElse(0), Option(c.code).getOrElse(""))
      Asset(
        key = AssetKey(file, op, alg, mode, if (alg=="AES" && mode=="GCM") "256" else ""),
        provider = "Libsodium",
        primitive = prim,
        pqCategory = pqCat,
        pqVulnerability = pqVuln,
        ivSource = Some(ivLen.getOrElse("")),
        properties = propsBase.toMap,
        weaknesses = weaknessTags(c.code, c.name),
        evidence = List(evi)
      )
    }
  }

  // Merge identical AssetKeys and unify properties/evidence
  assets.groupBy(_.key).map { case (k, xs) =>
    val one = xs.head
    val props = xs.map(_.properties).foldLeft(Map.empty[String,String])(_ ++ _)
    one.copy(
      properties = props,
      evidence = xs.flatMap(_.evidence).distinct.sortBy(e => (e.file, e.function, e.line)),
      weaknesses = xs.flatMap(_.weaknesses).distinct
    )
  }.toList
}

// -------- TLS pass --------
def scanTlsAssets(scopeRegex: String): List[Asset] = {
  val tlsCtx = cpg.method.where(_.file.name(scopeRegex)).l.filter { m =>
    m.call.name(TLS_CTX_NEW_RE).nonEmpty
  }
  tlsCtx.flatMap(gatherTls(_).map(_._1))
}

// -------- Impact edges --------
def impactEdges(scopeRegex: String): List[ImpactEdge] = {
  // in-scope, real files only (no <unknown>, no virtuals)
  val inScopeFiles: Set[String] =
    cpg.file.name(scopeRegex).name.l
      .filter(p => p.nonEmpty && !p.startsWith("<"))
      .toSet

  if (inScopeFiles.isEmpty) return Nil

  // Map: methodFullName -> (file, simpleName, isExternal)
  val defOwners: Map[String, (String, String, Boolean)] =
    cpg.method.l
      .map(m => m.fullName -> (m.file.name.headOption.getOrElse(""), m.name, m.isExternal))
      .toMap

  cpg.call.l.flatMap { c =>
    val callerM        = c.method
    val callerFile     = callerM.file.name.headOption.getOrElse("")
    val callerExternal = callerM.isExternal

    // In Joern, Call.methodFullName is the callee’s full name
    val calleeFull     = c.methodFullName
    defOwners.get(calleeFull).flatMap { case (calleeFile, calleeSimple, calleeExternal) =>
      val line = c.lineNumber.getOrElse(0)

      // Keep only strict, intra-repo file->file edges:
      //  - real files (not empty, not <unknown>)
      //  - both methods are non-external
      //  - files differ
      //  - both files are in the scope set
      val isRealCaller = callerFile.nonEmpty && !callerFile.startsWith("<")
      val isRealCallee = calleeFile.nonEmpty && !calleeFile.startsWith("<")

      if (isRealCaller && isRealCallee &&
          !callerExternal && !calleeExternal &&
          callerFile != calleeFile &&
          inScopeFiles.contains(callerFile) &&
          inScopeFiles.contains(calleeFile)) {
        Some(ImpactEdge(callerFile, calleeFile, callerM.fullName, calleeSimple, line))
      } else None
    }
  }.distinct
}

// -------- CBOM writer --------
def writeCbom(assets: List[Asset], edges: List[ImpactEdge], scopeRegex: String, outPath: String): Unit = {
  val repoRoot = Paths.get(REPO)
  val files = cpg.file.name(scopeRegex).name.l.distinct.filterNot(_.startsWith("<"))

  val outbound = edges.groupBy(_.srcFile)

  val fileComps = files.map { path =>
    val rel = Paths.get(path)
    val abs = if (rel.isAbsolute) rel else repoRoot.resolve(rel).normalize()
    val bytes = try { if (Files.isRegularFile(abs)) Some(Files.readAllBytes(abs)) else None } catch { case _: Throwable => None }
    val sha = bytes.map(sha256Hex).getOrElse("")
    val outboundArr = outbound.getOrElse(path, Nil).map { e =>
      s"""{"file":"${q(e.dstFile)}","caller":"${q(e.caller)}","callee":"${q(e.callee)}","line":${e.line}}"""
    }.mkString("[",",","]")
    val bref = s"file:${path}"
    s"""
    {
      "type":"file",
      "bom-ref":"${q(bref)}",
      "name":"${q(path)}",
      "hashes":[{"alg":"SHA-256","content":"${q(sha)}"}],
      "properties":[
        ${prop("impact.outbound.count", outbound.getOrElse(path, Nil).map(_.dstFile).distinct.size.toString)},
        ${prop("impact.outbound.edges", outboundArr)}
      ]
    }
    """
  }.mkString(",")

  val withRefs = assets.map { a =>
    val ev = a.evidence.head
    val idSeed = s"${ev.file}|${ev.function}|${ev.line}|${a.key.algorithm}|${a.key.mode}|${a.key.keySize}|${a.key.operation}|${a.primitive}"
    val bref = s"crypto:${stableId(idSeed)}"
    (a, bref)
  }

  val cryptoComps = withRefs.map { case (a, ref) =>
    val base = List(a.key.algorithm, a.key.keySize, a.key.mode).filter(_.nonEmpty).mkString("-")
    val display = if (base.nonEmpty) base else a.key.algorithm
    val evJson = a.evidence.map { e =>
      s"""{"file":"${q(e.file)}","function":"${q(e.function)}","line":${e.line},"snippet":"${q(e.snippet)}"}"""
    }.mkString("[",",","]")
    val propsKVs =
      a.properties ++ Map(
        "provider" -> a.provider,
        "operation" -> a.key.operation,
        "primitive" -> a.primitive,
        "weaknesses" -> a.weaknesses.mkString(","),
        "pqm.category" -> a.pqCategory,
        "pqm.vulnerability" -> a.pqVulnerability,
        "ivSource" -> a.ivSource.getOrElse("")
      )
    val props = propsKVs.map{ case(k,v) => prop(k, Option(v).getOrElse("")) }.mkString(",")
    s"""
    {
      "type":"data",
      "bom-ref":"$ref",
      "name":"${q(display)}",
      "properties":[ $props ],
      "evidence": { "occurrences": $evJson }
    }
    """
  }.mkString(",")

  val depsFileCrypto = withRefs.groupBy(_._1.key.file).toList.collect {
    case (file, pairs) if files.contains(file) =>
      val refs = pairs.map(_._2).map(r => s""""$r"""").mkString(",")
      s"""{"ref":"file:${q(file)}","dependsOn":[ $refs ]}"""
  }

  val depsFileFile = edges
    .filter(e => files.contains(e.srcFile) || files.contains(e.dstFile))
    .groupBy(_.srcFile).toList.collect {
      case (src, es) if files.contains(src) =>
        val dsts = es.map(_.dstFile).distinct.filter(files.contains).map(f => s""""file:${q(f)}"""").mkString(",")
        s"""{"ref":"file:${q(src)}","dependsOn":[ $dsts ]}"""
    }

  val componentsJson   = if (cryptoComps.nonEmpty) s"$fileComps,$cryptoComps" else fileComps
  val dependenciesJson = (depsFileCrypto ++ depsFileFile).mkString(",")

  val json =
  s"""
{
  "bomFormat":"CycloneDX",
  "specVersion":"1.6",
  "serialNumber":"urn:uuid:${UUID.randomUUID()}",
  "version":1,
  "metadata":{
    "timestamp":"${java.time.ZonedDateTime.now().toString}",
    "tools":[{"vendor":"Joern","name":"Joern-CBOM-OpenSSL+Libsodium","version":"df-v2.4.1"}]
  },
  "components":[
    $componentsJson
  ],
  "dependencies":[
    $dependenciesJson
  ]
}
"""
  val p = Paths.get(outPath)
  if (p.getParent != null) Files.createDirectories(p.getParent)
  Files.write(p, json.getBytes(java.nio.charset.StandardCharsets.UTF_8))
  println(s"Wrote CBOM -> $outPath")
}

// -------- Entrypoint --------
def cryptoScan(repo: String, out: String = "cbom.cdx.json", scopeRegex: String = ".*"): Unit = {
  REPO = repo; OUTFILE = out;
  if (cpg.metaData.l.isEmpty) importCode(repo)

  println(s"[info] Dataflow available: ${dfAvailable()}")
  println(s"[info] Scope regex: ${scopeRegex}")

  val evpAssets     = scanEVPAssets(scopeRegex)
  val tlsAssets     = scanTlsAssets(scopeRegex)
  val createAssets  = scanCreationAssets(scopeRegex) 
  val sodiumAssets  = scanSodiumAssets(scopeRegex)

  val assets = (evpAssets ++ tlsAssets ++ createAssets ++ sodiumAssets)

  println(s"[info] Crypto/TLS assets: ${assets.size}")

  val edges  = impactEdges(scopeRegex)
  println(s"[info] File edges: ${edges.size}")

  writeCbom(assets, edges, scopeRegex, OUTFILE)
  println(s"[done] CBOM -> $OUTFILE")
}

println(
  """Loaded opensslibsodium_cbom.sc.sc (OpenSSL + Libsodium).
Usage:
  :load /abs/path/opensslibsodium_cbom.sc.sc
  workspace.reset
  importCode("/abs/path/<repo>")
  cryptoScan("/abs/path/<repo>", "/abs/path/cbom.cdx.json", ".*")
""")

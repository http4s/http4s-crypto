/*
 * Copyright 2021 http4s.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.http4s.crypto

private[http4s] sealed trait Algorithm {
  private[crypto] def toStringJava: String
  private[crypto] def toStringNodeJS: String
  private[crypto] def toStringWebCrypto: String
}

private[http4s] sealed trait HashAlgorithm extends Algorithm
private[http4s] object HashAlgorithm {

  case object MD5 extends HashAlgorithm {
    private[crypto] override def toStringJava: String = "MD5"
    private[crypto] override def toStringNodeJS: String = "md5"
    private[crypto] override def toStringWebCrypto: String =
      throw new UnsupportedOperationException
  }

  case object SHA1 extends HashAlgorithm {
    private[crypto] override def toStringJava: String = "SHA-1"
    private[crypto] override def toStringNodeJS: String = "sha1"
    private[crypto] override def toStringWebCrypto: String = "SHA-1"
  }

  case object SHA256 extends HashAlgorithm {
    private[crypto] override def toStringJava: String = "SHA-256"
    private[crypto] override def toStringNodeJS: String = "sha256"
    private[crypto] override def toStringWebCrypto: String = "SHA-256"
  }

  case object SHA512 extends HashAlgorithm {
    private[crypto] override def toStringJava: String = "SHA-512"
    private[crypto] override def toStringNodeJS: String = "sha512"
    private[crypto] override def toStringWebCrypto: String = "SHA-512"
  }
}

private[http4s] sealed trait HmacAlgorithm extends Algorithm {
  private[crypto] def minimumKeyLength: Int
}
private[http4s] object HmacAlgorithm {

  private[crypto] def fromStringJava(algorithm: String): Option[HmacAlgorithm] =
    algorithm match {
      case "HmacSHA1" => Some(SHA1)
      case "HmacSHA256" => Some(SHA256)
      case "HmacSHA512" => Some(SHA512)
      case _ => None
    }

  case object SHA1 extends HmacAlgorithm {
    private[crypto] override def toStringJava: String = "HmacSHA1"
    private[crypto] override def toStringNodeJS: String = "sha1"
    private[crypto] override def toStringWebCrypto: String = "SHA-1"
    private[crypto] override def minimumKeyLength: Int = 20
  }

  case object SHA256 extends HmacAlgorithm {
    private[crypto] override def toStringJava: String = "HmacSHA256"
    private[crypto] override def toStringNodeJS: String = "sha256"
    private[crypto] override def toStringWebCrypto: String = "SHA-256"
    private[crypto] override def minimumKeyLength: Int = 32
  }

  case object SHA512 extends HmacAlgorithm {
    private[crypto] override def toStringJava: String = "HmacSHA512"
    private[crypto] override def toStringNodeJS: String = "sha512"
    private[crypto] override def toStringWebCrypto: String = "SHA-512"
    private[crypto] override def minimumKeyLength: Int = 64
  }
}

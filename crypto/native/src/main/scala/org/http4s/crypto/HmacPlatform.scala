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

import cats.ApplicativeThrow
import scodec.bits.ByteVector

import scala.scalanative.unsafe._
import scala.scalanative.unsigned._

private[crypto] trait HmacPlatform[F[_]]

private[crypto] trait HmacCompanionPlatform {
  implicit def forApplicativeThrow[F[_]](implicit F: ApplicativeThrow[F]): Hmac[F] =
    new UnsealedHmac[F] {

      def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] =
        Zone { implicit z =>
          import HmacAlgorithm._

          val SecretKeySpec(keyBytes, algorithm) = key

          val name = algorithm match {
            case SHA1 => c"SHA1"
            case SHA256 => c"SHA256"
            case SHA512 => c"SHA512"
          }

          val evpMd = openssl.evp.EVP_get_digestbyname(name)
          if (evpMd == null)
            F.raiseError(new GeneralSecurityException("EVP_get_digestbyname"))
          else {
            val md = stackalloc[CUnsignedChar](openssl.evp.EVP_MAX_MD_SIZE)
            val mdLen = stackalloc[CUnsignedInt]()

            if (openssl
                .hmac
                .HMAC(
                  evpMd,
                  keyBytes.toPtr,
                  keyBytes.size.toInt,
                  data.toPtr.asInstanceOf[Ptr[CUnsignedChar]],
                  data.size.toULong,
                  md,
                  mdLen) != null)
              F.pure(ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], (!mdLen).toLong))
            else
              F.raiseError(new GeneralSecurityException("HMAC"))
          }
        }

      def importKey[A <: HmacAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]] =
        F.pure(SecretKeySpec(key, algorithm))
    }
}

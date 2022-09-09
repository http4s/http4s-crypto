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

private[crypto] trait HashCompanionPlatform {
  implicit def forApplicativeThrow[F[_]](implicit F: ApplicativeThrow[F]): Hash[F] =
    new UnsealedHash[F] {
      def digest(algorithm: HashAlgorithm, data: ByteVector): F[ByteVector] =
        Zone { implicit z =>
          import HashAlgorithm._

          val name = algorithm match {
            case MD5 => c"MD5"
            case SHA1 => c"SHA1"
            case SHA256 => c"SHA256"
            case SHA512 => c"SHA512"
          }

          val `type` = openssl.evp.EVP_get_digestbyname(name)
          if (`type` == null)
            F.raiseError(new RuntimeException("EVP_get_digestbyname"))
          else {
            val md = stackalloc[CUnsignedChar](openssl.evp.EVP_MAX_MD_SIZE)
            val size = stackalloc[CUnsignedInt]()

            if (openssl
                .evp
                .EVP_Digest(data.toPtr, data.size.toULong, md, size, `type`, null) == 1)
              F.pure(ByteVector.fromPtr(md.asInstanceOf[Ptr[Byte]], (!size).toLong))
            else
              F.raiseError(new RuntimeException("EVP_DIGEST"))
          }
        }

    }
}

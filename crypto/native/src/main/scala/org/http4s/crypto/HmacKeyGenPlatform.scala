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

import cats.effect.kernel.Sync
import scodec.bits.ByteVector

import scala.scalanative.unsafe._

private[crypto] trait HmacKeyGenCompanionPlatform {
  implicit def forSync[F[_]](implicit F: Sync[F]): HmacKeyGen[F] =
    new UnsealedHmacKeyGen[F] {
      def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
        F.delay {
          val len = algorithm.minimumKeyLength
          val buf = stackalloc[Byte](len)
          if (openssl.rand.RAND_bytes(buf, len) != 1)
            throw new GeneralSecurityException("RAND_bytes")
          SecretKeySpec(ByteVector.fromPtr(buf, len.toLong), algorithm)
        }
    }
}

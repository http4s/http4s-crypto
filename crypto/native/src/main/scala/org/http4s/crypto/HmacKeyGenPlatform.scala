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
import cats.effect.std.SecureRandom
import cats.effect.SyncIO
import cats.syntax.all._
import scodec.bits.ByteVector

private[crypto] trait HmacKeyGenCompanionPlatform {
  implicit def forSync[F[_]](implicit F: Sync[F]): HmacKeyGen[F] =
    new UnsealedHmacKeyGen[F] {
      private val random = SecureRandom.javaSecuritySecureRandom[SyncIO].unsafeRunSync()
      def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
        random.nextBytes(algorithm.minimumKeyLength).to[F].map { bytes =>
          SecretKeySpec(ByteVector.view(bytes), algorithm)
        }
    }
}

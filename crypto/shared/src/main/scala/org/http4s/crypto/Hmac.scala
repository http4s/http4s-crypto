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

import scodec.bits.ByteVector

private[http4s] sealed trait Hmac[F[_]] extends HmacPlatform[F] {
  def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector]
  def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]]
  def importKey[A <: HmacAlgorithm](key: ByteVector, algorithm: A): F[SecretKey[A]]
}

private[crypto] trait UnsealedHmac[F[_]] extends Hmac[F]

private[http4s] object Hmac extends HmacCompanionPlatform {

  def apply[F[_]](implicit hmac: Hmac[F]): hmac.type = hmac

}

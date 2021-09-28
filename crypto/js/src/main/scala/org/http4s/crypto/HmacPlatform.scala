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
import cats.effect.kernel.Async
import cats.syntax.all._
import scodec.bits.ByteVector

import scala.scalajs.js

private[crypto] trait HmacPlatform[F[_]]

private[crypto] trait HmacCompanionPlatform {
  implicit def forAsyncOrApplicativeThrow[F[_]](
      implicit F0: Priority[Async[F], ApplicativeThrow[F]]): Hmac[F] =
    if (facade.isNodeJSRuntime)
      new UnsealedHmac[F] {
        import facade.node._
        implicit val F: ApplicativeThrow[F] = F0.join[ApplicativeThrow[F]]

        override def digest(key: SecretKey[HmacAlgorithm], data: ByteVector): F[ByteVector] =
          key match {
            case SecretKeySpec(key, algorithm) =>
              F.catchNonFatal {
                val hmac = crypto.createHmac(algorithm.toStringNodeJS, key.toUint8Array)
                hmac.update(data.toUint8Array)
                ByteVector.view(hmac.digest())
              }
            case _ => F.raiseError(new InvalidKeyException)
          }

        override def importKey[A <: HmacAlgorithm](
            key: ByteVector,
            algorithm: A): F[SecretKey[A]] =
          F.pure(SecretKeySpec(key, algorithm))

      }
    else
      F0.getPreferred
        .map { implicit F: Async[F] =>
          new UnsealedHmac[F] {
            import facade.browser._
            override def digest(
                key: SecretKey[HmacAlgorithm],
                data: ByteVector): F[ByteVector] =
              key match {
                case SecretKeySpec(key, algorithm) =>
                  for {
                    key <- F.fromPromise(
                      F.delay(
                        crypto
                          .subtle
                          .importKey(
                            "raw",
                            key.toUint8Array,
                            HmacImportParams(algorithm.toStringWebCrypto),
                            false,
                            js.Array("sign"))))
                    signature <- F.fromPromise(
                      F.delay(crypto.subtle.sign("HMAC", key, data.toUint8Array.buffer)))
                  } yield ByteVector.view(signature)
                case _ => F.raiseError(new InvalidKeyException)
              }
            override def importKey[A <: HmacAlgorithm](
                key: ByteVector,
                algorithm: A): F[SecretKey[A]] =
              F.pure(SecretKeySpec(key, algorithm))
          }
        }
        .getOrElse(throw new UnsupportedOperationException(
          "Hmac[F] on browsers requires Async[F]"))

}

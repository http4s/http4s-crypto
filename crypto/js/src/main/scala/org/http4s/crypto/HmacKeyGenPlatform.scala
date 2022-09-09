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

import cats.effect.kernel.Async
import cats.effect.kernel.Sync
import cats.syntax.all._
import scodec.bits.ByteVector

import scala.scalajs.js

private[crypto] trait HmacKeyGenCompanionPlatform {
  @deprecated("Preserved for bincompat", "0.2.3")
  def forAsyncOrSync[F[_]](implicit F0: Priority[Async[F], Sync[F]]): HmacKeyGen[F] =
    forSync(F0.join)

  implicit def forSync[F[_]](implicit F: Sync[F]): HmacKeyGen[F] =
    if (facade.isNodeJSRuntime)
      new UnsealedHmacKeyGen[F] {
        import facade.node._

        override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] = {
          val options = new GenerateKeyOptions {
            val length = algorithm.minimumKeyLength * java.lang.Byte.SIZE
          }
          Some(F)
            .collect { case f: Async[F] => f }
            .fold {
              F.delay[SecretKey[A]] {
                val key =
                  crypto.generateKeySync("hmac", options)
                SecretKeySpec(ByteVector.view(key.`export`()), algorithm)
              }
            } { F =>
              F.async_[SecretKey[A]] { cb =>
                crypto.generateKey(
                  "hmac",
                  options,
                  (err, key) =>
                    cb(
                      Option(err)
                        .map(js.JavaScriptException)
                        .toLeft(SecretKeySpec(ByteVector.view(key.`export`()), algorithm)))
                )
              }
            }
        }

      }
    else
      Some(F)
        .collect { case f: Async[F] => f }
        .fold(
          throw new UnsupportedOperationException("HmacKeyGen[F] on browsers requires Async[F]")
        ) { implicit F =>
          new UnsealedHmacKeyGen[F] {
            import facade.browser._
            override def generateKey[A <: HmacAlgorithm](algorithm: A): F[SecretKey[A]] =
              for {
                key <- F.fromPromise(
                  F.delay(
                    crypto
                      .subtle
                      .generateKey(
                        HmacKeyGenParams(algorithm.toStringWebCrypto),
                        true,
                        js.Array("sign"))))
                exported <- F.fromPromise(F.delay(crypto.subtle.exportKey("raw", key)))
              } yield SecretKeySpec(ByteVector.view(exported), algorithm)
          }
        }

}

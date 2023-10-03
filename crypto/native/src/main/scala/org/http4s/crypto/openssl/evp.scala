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

package org.http4s.crypto.openssl

import scala.annotation.nowarn
import scala.scalanative.unsafe._

@extern
@nowarn
private[crypto] object evp {

  final val EVP_MAX_MD_SIZE = 64

  def EVP_Digest(
      data: Ptr[Byte],
      count: CSize,
      md: Ptr[CUnsignedChar],
      size: Ptr[CUnsignedInt],
      `type`: Ptr[Byte],
      impl: Ptr[Byte]
  ): CInt = extern

  def EVP_get_digestbyname(name: Ptr[CChar]): Ptr[Byte] = extern

}

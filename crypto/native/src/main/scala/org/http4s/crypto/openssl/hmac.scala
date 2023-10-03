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

import org.typelevel.scalaccompat.annotation._

import scala.scalanative.unsafe._

@link("crypto")
@extern
@nowarn212
private[crypto] object hmac {

  def HMAC(
      evp_md: Ptr[Byte],
      key: Ptr[Byte],
      key_len: Int,
      d: Ptr[CUnsignedChar],
      n: CSize,
      md: Ptr[CUnsignedChar],
      md_len: Ptr[CUnsignedInt]
  ): Ptr[CUnsignedChar] = extern

}

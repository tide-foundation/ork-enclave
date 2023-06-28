// 
// Tide Protocol - Infrastructure for a TRUE Zero-Trust paradigm
// Copyright (C) 2022 Tide Foundation Ltd
// 
// This program is free software and is subject to the terms of 
// the Tide Community Open Code License as published by the 
// Tide Foundation Limited. You may modify it and redistribute 
// it in accordance with and subject to the terms of that License.
// This program is distributed WITHOUT WARRANTY of any kind, 
// including without any implied warranty of MERCHANTABILITY or 
// FITNESS FOR A PARTICULAR PURPOSE.
// See the Tide Community Open Code License for more details.
// You should have received a copy of the Tide Community Open 
// Code License along with this program.
// If not, see https://tide.org/licenses_tcoc2-0-0-en
//

import { mod, mod_inv } from "../Tools/Utils.js";

/**
 * @param {bigint} xi
 * @param {bigint[]} xs 
 * @param {bigint} m 
 * @returns {bigint}
 */
export function GetLi(xi, xs, m) {
    var li = xs.filter(xj => xj != xi)
        .map(xj => mod(mod_inv(xj-xi, m) * xj), m)
        .reduce((li, num) => mod(li * num, m));
    return li;
}
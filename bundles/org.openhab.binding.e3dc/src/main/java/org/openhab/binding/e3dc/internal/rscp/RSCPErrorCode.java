/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.e3dc.internal.rscp;

import java.util.HashMap;
import java.util.Map;

import org.openhab.binding.e3dc.internal.rscp.util.ByteUtils;

/**
 * Defines possible error codes
 *
 */
public enum RSCPErrorCode {

    RSCP_ERR_NOT_HANDLED("00000001"),
    RSCP_ERR_ACCESS_DENIED("00000002"),
    RSCP_ERR_FORMAT("00000003"),
    RSCP_ERR_AGAIN("00000004"),
    RSCP_ERR_OUT_OF_BOUNDS("00000005"),
    RSCP_ERR_NOT_AVAILABLE("00000006"),
    RSCP_ERR_UNKNOWN_TAG("00000007"),
    RSCP_ERR_ALREADY_IN_USE("00000008"),

    UNKNOWN("FFFFFFFF");

    private static final Map<String, RSCPErrorCode> HEX_STRING_TO_ERROR_CODE = new HashMap<>();

    static {
        for (RSCPErrorCode tag : values()) {
            HEX_STRING_TO_ERROR_CODE.put(ByteUtils.byteArrayToHexString(tag.getValueAsBytes()), tag);
        }
    }

    private final String hexString;

    RSCPErrorCode(String hexString) {
        this.hexString = hexString;
    }

    public static RSCPErrorCode getTagForHexString(String hexString) {
        return HEX_STRING_TO_ERROR_CODE.get(hexString);
    }

    public static RSCPErrorCode getTagForBytes(byte[] bytes) {
        return HEX_STRING_TO_ERROR_CODE.get(ByteUtils.byteArrayToHexString(bytes));
    }

    public byte[] getValueAsBytes() {
        return ByteUtils.hexStringToByteArray(this.hexString);
    }

    public String getValue() {
        return this.hexString;
    }
}

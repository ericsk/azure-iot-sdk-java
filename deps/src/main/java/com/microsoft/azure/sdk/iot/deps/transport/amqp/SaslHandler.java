/*
*  Copyright (c) Microsoft. All rights reserved.
*  Licensed under the MIT license. See LICENSE file in the project root for full license information.
*/

package com.microsoft.azure.sdk.iot.deps.transport.amqp;

public interface SaslHandler
{
    public enum SaslOutcome
    {
        /** negotiation not completed */
        PN_SASL_NONE,

        /** authentication succeeded */
        PN_SASL_OK,

        /** failed due to bad credentials */
        PN_SASL_AUTH,

        /** failed due to a system error */
        PN_SASL_SYS,

        /** failed due to unrecoverable error */
        PN_SASL_PERM,

        /** failed due to transient error */
        PN_SASL_TEMP,
        PN_SASL_SKIPPED
    }

    byte[] handleSaslMechanisms(String[] mechanisms);

    byte[] handleChallenge(byte[] saslChallenge);

    void handleOutcome(SaslOutcome outcome);
}

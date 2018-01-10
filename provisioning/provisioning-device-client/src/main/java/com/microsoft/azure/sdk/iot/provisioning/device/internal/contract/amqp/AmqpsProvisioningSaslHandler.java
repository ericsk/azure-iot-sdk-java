/*
*  Copyright (c) Microsoft. All rights reserved.
*  Licensed under the MIT license. See LICENSE file in the project root for full license information.
*/

package com.microsoft.azure.sdk.iot.provisioning.device.internal.contract.amqp;

import com.microsoft.azure.sdk.iot.deps.transport.amqp.SaslHandler;

import java.io.IOException;

public class AmqpsProvisioningSaslHandler implements SaslHandler
{
    private final static String TPM_MECHANISM = "TPM";
    private final static byte NULL_BYTE = (byte) '\0';
    private final static byte FINAL_SEGMENT_CONTROL_BYTE = (byte) 192; // TODO document is outdated? These masks are not accepted at appropriate times, but 00000000 is. Ask Rajeev
    private final static byte INTERMEDIATE_SEGMENT_CONTROL_BYTE = (byte) 128;
    private final static byte INIT_SEGMENT_CONTROL_BYTE = (byte) 0;
    private final static long MAX_MILLISECONDS_TIMEOUT_FOR_SAS_TOKEN_WAIT = 3*60*1000; // 3 minutes

    private String idScope;
    private String registrationId;
    private byte[] endorsementKey;
    private byte[] srk;
    private byte[] challengeKey;
    private ChallengeState challengeState;
    private ProvisioningAmqpNonceCallback nonceCallback;
    private String sasToken;

    private enum ChallengeState
    {
        SENDING_INIT,
        WAITING_FOR_FIRST_CHALLENGE,
        WAITING_FOR_SECOND_CHALLENGE,
        WAITING_FOR_THIRD_CHALLENGE,
        WAITING_TO_SEND_SAS_TOKEN,
        WAITING_FOR_FINAL_OUTCOME
    }

    AmqpsProvisioningSaslHandler(String idScope, String registrationId, byte[] endorsementKey, byte[] srk, ProvisioningAmqpNonceCallback nonceCallback)
    {
        this.idScope = idScope;
        this.registrationId = registrationId;
        this.endorsementKey = endorsementKey;
        this.srk = srk;
        this.nonceCallback = nonceCallback;
        this.challengeState = ChallengeState.SENDING_INIT;
        this.sasToken = null;
    }

    public byte[] handleSaslMechanisms(String[] mechanisms)
    {
        boolean tpmMechanismOfferedByService = false;
        for (String mechanism : mechanisms)
        {
            tpmMechanismOfferedByService |= mechanism.equals(TPM_MECHANISM);
        }

        if (!tpmMechanismOfferedByService)
        {
            throw new SecurityException("Service endpoint does not support TPM authentication");
        }

        byte[] saslInitBytes = buildSaslInitPayload(this.idScope, this.registrationId, this.endorsementKey);
        this.challengeState = ChallengeState.WAITING_FOR_FIRST_CHALLENGE;
        return saslInitBytes;
    }

    public byte[] handleChallenge(byte[] saslChallenge)
    {
        switch (challengeState)
        {
            case SENDING_INIT:
                throw new IllegalStateException("Received a challenge before sending Sasl init frames");

            case WAITING_FOR_FIRST_CHALLENGE:
                this.challengeState = ChallengeState.WAITING_FOR_SECOND_CHALLENGE;
                return handleFirstChallenge(saslChallenge);

            case WAITING_FOR_SECOND_CHALLENGE:
                return handleSecondChallenge(saslChallenge);

            case WAITING_FOR_THIRD_CHALLENGE:
                return handleThirdChallenge(saslChallenge);

            default:
                throw new IllegalStateException("Unexpected challenge received when expected Sasl outcome");
        }
    }

    public void handleOutcome(SaslOutcome outcome)
    {
        switch (outcome)
        {
            case PN_SASL_OK:
                //auth successful
                break;

            case PN_SASL_AUTH:
                //bad credentials
                throw new SecurityException("Sas token was rejected by the service");

            case PN_SASL_SYS:
            case PN_SASL_NONE:
            case PN_SASL_PERM:
            case PN_SASL_TEMP:
            case PN_SASL_SKIPPED:
            default:
                //some other kind of failure
                throw new SecurityException("Sasl authentication against service failed");
        }
    }

    void setSasToken(String sasToken)
    {
        this.sasToken = sasToken;
    }

    private byte[] handleFirstChallenge(byte[] challengeData)
    {
        //validate challenge
        if (challengeData.length != 1 || challengeData[0] != NULL_BYTE)
        {
            throw new IllegalStateException("Unexpected challenge data");
        }

        //send response
        return buildFirstSaslChallengeResponsePayload(this.srk);
    }

    private byte[] handleSecondChallenge(byte[] challengeData)
    {
        //validate challenge
        if (challengeData.length == 0 || challengeData == null)
        {
            throw new IllegalStateException("Unexpected challenge data");
        }

        this.challengeState = ChallengeState.WAITING_FOR_THIRD_CHALLENGE;

        //send response
        this.challengeKey = new byte[challengeData.length-1];
        System.arraycopy(challengeData, 1, this.challengeKey, 0, challengeData.length-1);
        return new byte[]{0};
    }

    private byte[] handleThirdChallenge(byte[] challengeData)
    {
        this.challengeKey = buildNonceFromThirdChallenge(challengeData);
        this.nonceCallback.giveNonce(this.challengeKey);
        this.challengeState = ChallengeState.WAITING_TO_SEND_SAS_TOKEN;

        long millisecondsElapsed = 0;
        long waitTimeStart = System.currentTimeMillis();
        while (this.sasToken == null && millisecondsElapsed < MAX_MILLISECONDS_TIMEOUT_FOR_SAS_TOKEN_WAIT)
        {
            try
            {
                Thread.sleep(1000);
            }
            catch (InterruptedException e)
            {
                if (this.sasToken == null)
                {
                    throw new SecurityException("Sasl negotiation failed");
                }
            }

            millisecondsElapsed += System.currentTimeMillis() - waitTimeStart;
        }

        if (millisecondsElapsed >= MAX_MILLISECONDS_TIMEOUT_FOR_SAS_TOKEN_WAIT)
        {
            throw new SecurityException("Sasl negotiation failed: Sas token was never supplied to finish negotiation");
        }

        this.challengeState = ChallengeState.WAITING_FOR_FINAL_OUTCOME;
        return prependByteArrayWithControlByte(INIT_SEGMENT_CONTROL_BYTE, sasToken.getBytes());
    }

    private byte[] buildNonceFromThirdChallenge(byte[] challengeData)
    {
        //TODO why do I have to peel off the beginning byte for the challenge keys? Ask rajeev?
        byte[] completeChallengeKey = new byte[this.challengeKey.length + challengeData.length - 1];
        System.arraycopy(this.challengeKey, 0, completeChallengeKey, 0, this.challengeKey.length);
        System.arraycopy(challengeData, 1, completeChallengeKey, this.challengeKey.length, challengeData.length - 1);
        return completeChallengeKey;
    }

    private static byte[] buildSaslInitPayload(String idScope, String registrationId, byte[] endorsementKey)
    {
        byte[] bytes = concatBytesWithNullDelimiter(idScope.getBytes(), registrationId.getBytes(), endorsementKey);
        return prependByteArrayWithControlByte(INIT_SEGMENT_CONTROL_BYTE, bytes);
    }

    private static byte[] buildFirstSaslChallengeResponsePayload(byte[] srk)
    {
        return prependByteArrayWithControlByte(INIT_SEGMENT_CONTROL_BYTE, srk);
    }

    private static byte[] concatBytesWithNullDelimiter(byte[]...arrays)
    {
        // Determine the length of the result array
        int totalLength = 0;
        for (int i = 0; i < arrays.length; i++)
        {
            totalLength += arrays[i].length;
        }

        //for X arrays, there will be X-1 delimiters
        totalLength += arrays.length - 1;

        // create the result array
        byte[] result = new byte[totalLength];

        // copy the source arrays into the result array
        int currentIndex = 0;
        for (int i = 0; i < arrays.length-1; i++)
        {
            //copy the source array into the single new array
            System.arraycopy(arrays[i], 0, result, currentIndex, arrays[i].length);

            //add the UTF8NUL delimiter
            result[currentIndex + arrays[i].length] = NULL_BYTE;

            currentIndex += arrays[i].length + 1;
        }

        //copy the final value into the array without adding a delimiter at the end
        System.arraycopy(arrays[arrays.length-1], 0, result, currentIndex, arrays[arrays.length-1].length);

        return result;
    }

    private static byte[] prependByteArrayWithControlByte(byte controlByte, byte[] bytes)
    {
        byte[] newByteArray = new byte[bytes.length + 1];
        newByteArray[0] = controlByte;
        System.arraycopy(bytes, 0, newByteArray, 1, bytes.length);
        return newByteArray;
    }
}

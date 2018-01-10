package com.microsoft.azure.sdk.iot.deps.transport.amqp;

import org.apache.qpid.proton.engine.Sasl;
import org.apache.qpid.proton.engine.SaslListener;
import org.apache.qpid.proton.engine.Transport;

public class SaslListenerImpl implements SaslListener
{
    private SaslHandler saslHandler;

    public SaslListenerImpl(SaslHandler saslHandler)
    {
        this.saslHandler = saslHandler;
    }

    public void onSaslMechanisms(Sasl sasl, Transport transport)
    {
        String[] mechanisms = sasl.getRemoteMechanisms();
        sasl.setMechanisms(mechanisms);
        byte[] initMessage = this.saslHandler.handleSaslMechanisms(mechanisms);
        sasl.send(initMessage, 0, initMessage.length);
    }

    public void onSaslChallenge(Sasl sasl, Transport transport)
    {
        byte[] saslChallenge = new byte[sasl.pending()];
        sasl.recv(saslChallenge, 0, saslChallenge.length);
        byte[] challengeResponse = this.saslHandler.handleChallenge(saslChallenge);
        sasl.send(challengeResponse, 0, challengeResponse.length);
    }

    public void onSaslOutcome(Sasl sasl, Transport transport)
    {
        switch (sasl.getOutcome())
        {
            case PN_SASL_SKIPPED:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_SKIPPED);
                break;
            case PN_SASL_TEMP:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_TEMP);
                break;
            case PN_SASL_PERM:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_PERM);
                break;
            case PN_SASL_NONE:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_NONE);
                break;
            case PN_SASL_AUTH:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_AUTH);
                break;
            case PN_SASL_OK:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_OK);
                break;
            case PN_SASL_SYS:
            default:
                this.saslHandler.handleOutcome(SaslHandler.SaslOutcome.PN_SASL_SYS);
                break;
        }
    }

    public void onSaslResponse(Sasl sasl, Transport transport)
    {
        //do nothing. This implementation is used for devices only, not services
    }

    public void onSaslInit(Sasl sasl, Transport transport)
    {
        //do nothing. This implementation is used for devices only, not services
    }
}

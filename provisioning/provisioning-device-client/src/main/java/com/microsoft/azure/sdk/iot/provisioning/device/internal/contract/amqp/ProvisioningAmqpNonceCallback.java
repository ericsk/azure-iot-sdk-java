package com.microsoft.azure.sdk.iot.provisioning.device.internal.contract.amqp;

public interface ProvisioningAmqpNonceCallback
{
    public void giveNonce(byte[] nonceBytes);
}

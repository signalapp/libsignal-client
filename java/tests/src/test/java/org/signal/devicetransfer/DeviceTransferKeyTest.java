//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

package org.signal.libsignal.devicetransfer;

import junit.framework.TestCase;
import javax.security.cert.X509Certificate;

public class DeviceTransferKeyTest extends TestCase {
  public void testDeviceTransferKey() throws Exception {
    DeviceTransferKey key = new DeviceTransferKey();
    byte[] certBytes = key.generateCertificate("name", 365);

    X509Certificate cert = X509Certificate.getInstance(certBytes);
  }
}

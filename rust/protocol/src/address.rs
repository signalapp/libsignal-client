//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

/// A *device* is a particular Signal client instance which represents some user.
///
/// For example, a user may have set up Signal on both their phone and laptop. Any
/// [crate::SignalMessage] sent to the user will still only go to a single device, so when a user
/// sends a message to another user at all, they're actually sending a message to *every* device.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct DeviceId(u32);

impl From<u32> for DeviceId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<DeviceId> for u32 {
    fn from(value: DeviceId) -> Self {
        value.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct ProtocolAddress {
    name: String,
    device_id: DeviceId,
}

impl ProtocolAddress {
    pub fn new(name: String, device_id: DeviceId) -> Self {
        ProtocolAddress { name, device_id }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.name, self.device_id)
    }
}

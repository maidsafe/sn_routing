// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use client_error::ClientError;
use data::{ImmutableData, PermissionSet, User, Value};
use rust_sodium::crypto::sign;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
use types::MessageId as MsgId;

/// Response message types
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Response {
    /// Returns a success or failure status of account information retrieval.
    GetAccountInfo {
        /// Result of fetching account info from the network.
        res: Result<AccountInfo, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- ImmutableData ---
    // ==========================
    /// Returns a success or failure status of putting ImmutableData to the network.
    PutIData {
        /// Result of putting ImmutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a result of fetching ImmutableData from the network.
    GetIData {
        /// Result of fetching ImmutableData from the network.
        res: Result<ImmutableData, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- MutableData ---
    // ==========================
    /// Returns a success or failure status of putting MutableData to the network.
    PutMData {
        /// Result of putting MutableData to the network.
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    /// Returns a current version of MutableData stored in the network.
    GetMDataVersion {
        /// Result of getting a version of MutableData
        res: Result<u64, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Data Actions
    /// Returns a complete list of entries in MutableData or an error in case of failure.
    ListMDataEntries {
        /// Result of getting a list of entries in MutableData
        res: Result<BTreeMap<Vec<u8>, Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of keys in MutableData or an error in case of failure.
    ListMDataKeys {
        /// Result of getting a list of keys in MutableData
        res: Result<BTreeSet<Vec<u8>>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of values in MutableData or an error in case of failure.
    ListMDataValues {
        /// Result of getting a list of values in MutableData
        res: Result<Vec<Value>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a single entry from MutableData or an error in case of failure.
    GetMDataValue {
        /// Result of getting a value from MutableData
        res: Result<Value, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of mutating MutableData in the network.
    MutateMDataEntries {
        /// Result of mutating an entry in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Permission Actions
    /// Returns a complete list of MutableData permissions stored on the network
    /// or an error in case of failure.
    ListMDataPermissions {
        /// Result of getting a list of permissions in MutableData
        res: Result<BTreeMap<User, PermissionSet>, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a list of permissions for a particular User in MutableData or an
    /// error in case of failure.
    ListMDataUserPermissions {
        /// Result of getting a list of user permissions in MutableData
        res: Result<PermissionSet, ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of setting permissions for a particular
    /// User in MutableData.
    SetMDataUserPermissions {
        /// Result of setting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting permissions for a particular
    /// User in MutableData.
    DelMDataUserPermissions {
        /// Result of deleting a list of user permissions in MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // Ownership Actions
    /// Returns a success or failure status of chaning an owner of MutableData.
    ChangeMDataOwner {
        /// Result of chaning an owner of MutableData
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },

    // --- Client (Owner) to MM ---
    // ==========================
    /// Returns a list of authorised keys from MaidManager and the account version.
    ListAuthKeysAndVersion {
        /// Result of getting a list of authorised keys and version
        res: Result<(BTreeSet<sign::PublicKey>, u64), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of inserting an authorised key into MaidManager.
    InsAuthKey {
        /// Result of inserting an authorised key
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
    /// Returns a success or failure status of deleting an authorised key from MaidManager.
    DelAuthKey {
        /// Result of deleting an authorised key
        res: Result<(), ClientError>,
        /// Unique message identifier
        msg_id: MsgId,
    },
}

impl Response {
    /// The priority Crust should send this message with.
    pub fn priority(&self) -> u8 {
        /*
        match *self {
            Response::GetSuccess(ref data, _) => {
                match *data {
                    Data::Structured(..) => 4,
                    _ => 5,
                }
            }
            Response::PutSuccess(..) |
            Response::PostSuccess(..) |
            Response::DeleteSuccess(..) |
            Response::AppendSuccess(..) |
            Response::GetAccountInfoSuccess { .. } |
            Response::GetFailure { .. } |
            Response::PutFailure { .. } |
            Response::PostFailure { .. } |
            Response::DeleteFailure { .. } |
            Response::AppendFailure { .. } |
            Response::GetAccountInfoFailure { .. } => 3,
        }
        */

        unimplemented!()
    }

    /// Is this response cacheable?
    pub fn is_cacheable(&self) -> bool {
        if let Response::GetIData { .. } = *self {
            true
        } else {
            false
        }
    }
}

fn decode_result<D: Decoder, T: Decodable>(s: &mut D) -> Result<Result<T, ClientError>, D::Error> {
    Ok(match s.read_u8()? {
        0 => Ok(T::decode(s)?),
        1 => Err(ClientError::decode(s)?),
        _ => return Err(s.error("unexpected Result binary format: must be 0 or 1")),
    })
}

fn decode_response_variant<D: Decoder, T: Decodable>
    (s: &mut D)
     -> Result<(Result<T, ClientError>, MsgId), D::Error> {
    let res = s.read_enum_struct_variant_field("res", 0, |s| decode_result(s))?;
    let msg_id = s.read_enum_struct_variant_field("msg_id", 1, |s| MsgId::decode(s))?;
    Ok((res, msg_id))
}

impl Decodable for Response {
    fn decode<D: Decoder>(s: &mut D) -> Result<Self, D::Error> {
        s.read_enum("Response", |s| {
            s.read_enum_struct_variant(&["GetAccountInfo",
                                         "PutIData",
                                         "GetIData",
                                         "PutMData",
                                         "GetMDataVersion",
                                         "ListMDataEntries",
                                         "ListMDataKeys",
                                         "ListMDataValues",
                                         "GetMDataValue",
                                         "MutateMDataEntries",
                                         "ListMDataPermissions",
                                         "ListMDataUserPermissions",
                                         "SetMDataUserPermissions",
                                         "DelMDataUserPermissions",
                                         "ChangeMDataOwner",
                                         "ListAuthKeysAndVersion",
                                         "InsAuthKey",
                                         "DelAuthKey"],
                                       |s, num| {
                match num {
                    0 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::GetAccountInfo {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    1 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::PutIData {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    2 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::GetIData {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    3 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::PutMData {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    4 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::GetMDataVersion {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    5 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListMDataEntries {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    6 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListMDataKeys {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    7 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListMDataValues {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    8 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::GetMDataValue {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    9 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::MutateMDataEntries {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    10 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListMDataPermissions {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    11 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListMDataUserPermissions {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    12 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::SetMDataUserPermissions {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    13 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::DelMDataUserPermissions {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    14 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ChangeMDataOwner {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    15 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::ListAuthKeysAndVersion {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    16 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::InsAuthKey {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    17 => {
                        let (res, msg_id) = decode_response_variant(s)?;
                        Ok(Response::DelAuthKey {
                            res: res,
                            msg_id: msg_id,
                        })
                    }
                    _ => Err(s.error("Unknown Response type")),
                }
            })
        })
    }
}

fn encode_result<E: Encoder, T: Encodable>(encoder: &mut E,
                                           res: &Result<T, ClientError>)
                                           -> Result<(), E::Error> {
    match *res {
        Ok(ref val) => {
            encoder.emit_u8(0)?;
            val.encode(encoder)?;
        }
        Err(ref err) => {
            encoder.emit_u8(1)?;
            err.encode(encoder)?;
        }
    }
    Ok(())
}

fn encode_response_variant<S: Encoder, T: Encodable>(s: &mut S,
                                                     v_name: &str,
                                                     v_id: usize,
                                                     res: &Result<T, ClientError>,
                                                     msg_id: &MsgId)
                                                     -> Result<(), S::Error> {
    s.emit_enum_variant(v_name, v_id, 2, |s| {
        s.emit_enum_struct_variant_field("res", 0, |s| encode_result(s, res))?;
        s.emit_enum_struct_variant_field("msg_id", 1, |s| msg_id.encode(s))?;
        Ok(())
    })
}

impl Encodable for Response {
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {
        s.emit_enum("Response", |s| {
            match *self {
                Response::GetAccountInfo { ref res, ref msg_id } => {
                    encode_response_variant(s, "GetAccountInfo", 0, res, msg_id)
                }
                Response::PutIData { ref res, ref msg_id } => {
                    encode_response_variant(s, "PutIData", 1, res, msg_id)
                }
                Response::GetIData { ref res, ref msg_id } => {
                    encode_response_variant(s, "GetIData", 2, res, msg_id)
                }
                Response::PutMData { ref res, ref msg_id } => {
                    encode_response_variant(s, "PutMData", 3, res, msg_id)
                }
                Response::GetMDataVersion { ref res, ref msg_id } => {
                    encode_response_variant(s, "GetMDataVersion", 4, res, msg_id)
                }
                Response::ListMDataEntries { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListMDataEntries", 5, res, msg_id)
                }
                Response::ListMDataKeys { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListMDataKeys", 6, res, msg_id)
                }
                Response::ListMDataValues { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListMDataValues", 7, res, msg_id)
                }
                Response::GetMDataValue { ref res, ref msg_id } => {
                    encode_response_variant(s, "GetMDataValue", 8, res, msg_id)
                }
                Response::MutateMDataEntries { ref res, ref msg_id } => {
                    encode_response_variant(s, "MutateMDataEntries", 9, res, msg_id)
                }
                Response::ListMDataPermissions { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListMDataPermissions", 10, res, msg_id)
                }
                Response::ListMDataUserPermissions { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListMDataUserPermissions", 11, res, msg_id)
                }
                Response::SetMDataUserPermissions { ref res, ref msg_id } => {
                    encode_response_variant(s, "SetMDataUserPermissions", 12, res, msg_id)
                }
                Response::DelMDataUserPermissions { ref res, ref msg_id } => {
                    encode_response_variant(s, "DelMDataUserPermissions", 13, res, msg_id)
                }
                Response::ChangeMDataOwner { ref res, ref msg_id } => {
                    encode_response_variant(s, "ChangeMDataOwner", 14, res, msg_id)
                }
                Response::ListAuthKeysAndVersion { ref res, ref msg_id } => {
                    encode_response_variant(s, "ListAuthKeysAndVersion", 15, res, msg_id)
                }
                Response::InsAuthKey { ref res, ref msg_id } => {
                    encode_response_variant(s, "InsAuthKey", 16, res, msg_id)
                }
                Response::DelAuthKey { ref res, ref msg_id } => {
                    encode_response_variant(s, "DelAuthKey", 17, res, msg_id)
                }
            }
        })
    }
}

impl Debug for Response {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            Response::GetAccountInfo { ref res, ref msg_id } => {
                write!(formatter,
                       "GetAccountInfo {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::PutIData { ref res, ref msg_id } => {
                write!(formatter,
                       "PutIData {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::GetIData { ref res, ref msg_id } => {
                write!(formatter,
                       "GetIData {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::PutMData { ref res, ref msg_id } => {
                write!(formatter,
                       "PutMData {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::GetMDataVersion { ref res, ref msg_id } => {
                write!(formatter,
                       "GetMDataVersion {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListMDataEntries { ref res, ref msg_id } => {
                write!(formatter,
                       "ListMDataEntries {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListMDataKeys { ref res, ref msg_id } => {
                write!(formatter,
                       "ListMDataKeys {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListMDataValues { ref res, ref msg_id } => {
                write!(formatter,
                       "ListMDataValues {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::GetMDataValue { ref res, ref msg_id } => {
                write!(formatter,
                       "GetMDataValue {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::MutateMDataEntries { ref res, ref msg_id } => {
                write!(formatter,
                       "MutateMDataEntries {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListMDataPermissions { ref res, ref msg_id } => {
                write!(formatter,
                       "ListMDataPermissions {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListMDataUserPermissions { ref res, ref msg_id } => {
                write!(formatter,
                       "ListMDataUserPermissions {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::SetMDataUserPermissions { ref res, ref msg_id } => {
                write!(formatter,
                       "SetMDataUserPermissions {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::DelMDataUserPermissions { ref res, ref msg_id } => {
                write!(formatter,
                       "DelMDataUserPermissions {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ChangeMDataOwner { ref res, ref msg_id } => {
                write!(formatter,
                       "ChangeMDataOwner {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::ListAuthKeysAndVersion { ref res, ref msg_id } => {
                write!(formatter,
                       "ListAuthKeysAndVersion {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::InsAuthKey { ref res, ref msg_id } => {
                write!(formatter,
                       "InsAuthKey {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
            Response::DelAuthKey { ref res, ref msg_id } => {
                write!(formatter,
                       "DelAuthKey {{ res: {:?}, msg_id: {:?} }}",
                       res,
                       msg_id)
            }
        }
    }
}

/// Account information
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd, RustcDecodable, RustcEncodable, Debug)]
pub struct AccountInfo {
    /// Number of mutate operations performed by the account.
    pub mutations_done: u64,
    /// Number of mutate operations remaining for the account.
    pub mutations_available: u64,
}

#[cfg(test)]
mod tests {
    use client_error::ClientError;
    use maidsafe_utilities::serialisation::{deserialise, serialise};
    use super::*;
    use types::MessageId;

    #[test]
    fn serialise_response_err() {
        let msg_id = MessageId::new();
        let serialised = unwrap!(serialise(&Response::GetAccountInfo {
            res: Err(ClientError::NoSuchData),
            msg_id: msg_id,
        }));

        let deserialised = unwrap!(deserialise::<Response>(&serialised));

        if let Response::GetAccountInfo { res, msg_id: got_msg_id } = deserialised {
            assert!(if let Err(ClientError::NoSuchData) = res {
                        true
                    } else {
                        false
                    },
                    "Expected Err(ClientError::NoSuchData), got {:?}",
                    res);
            assert_eq!(got_msg_id, msg_id);
        } else {
            panic!("Expected Response::GetAccountInfo, got {:?}", deserialised);
        }
    }

    #[test]
    fn serialise_response_ok() {
        let msg_id = MessageId::new();
        let serialised = unwrap!(serialise(&Response::GetAccountInfo {
            res: Ok(AccountInfo {
                mutations_done: 64,
                mutations_available: 128,
            }),
            msg_id: msg_id,
        }));

        let deserialised = unwrap!(deserialise::<Response>(&serialised));

        if let Response::GetAccountInfo { res, msg_id: got_msg_id } = deserialised {
            let res = unwrap!(res);
            assert_eq!(res.mutations_done, 64);
            assert_eq!(res.mutations_available, 128);
            assert_eq!(got_msg_id, msg_id);
        } else {
            panic!("Expected Response::GetAccountInfo, got {:?}", deserialised);
        }
    }

    #[test]
    fn serialise_response_ok2() {
        let msg_id = MessageId::new();
        let serialised = unwrap!(serialise(&Response::ChangeMDataOwner {
            res: Ok(()),
            msg_id: msg_id,
        }));

        let deserialised = unwrap!(deserialise::<Response>(&serialised));
        if let Response::ChangeMDataOwner { res, msg_id: got_msg_id } = deserialised {
            assert!(res.is_ok());
            assert_eq!(got_msg_id, msg_id);
        } else {
            panic!("Expected Response::ChangeMDataOwner, got {:?}",
                   deserialised);
        }
    }
}

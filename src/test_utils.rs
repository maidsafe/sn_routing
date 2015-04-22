use types::*;
use rand::random;
use messages;

pub trait Random {
	fn generate_random() -> Self;
}

impl Random for DhtId {
	fn generate_random() -> DhtId {
		   DhtId(generate_random_vec_u8(64))
	}
}

impl Random for NameAndTypeId {
	fn generate_random() -> NameAndTypeId {
        NameAndTypeId {
            name: generate_random_vec_u8(64),
            type_id: random::<u32>(),
        }
    }
}

impl Random for Signature {
	fn generate_random() -> Signature {
		Signature { signature: generate_random_vec_u8(32) }
	}
}

impl Random for PublicSignKey {
	fn generate_random() -> PublicSignKey {
		PublicSignKey { public_sign_key: generate_random_vec_u8(32) }
	}
}

impl Random for PublicKey {
	fn generate_random() -> PublicKey {
		PublicKey { public_key: generate_random_vec_u8(32) }
	}
}

impl Random for PublicPmid {
	fn generate_random() -> PublicPmid {
      	PublicPmid {
	        public_key : Random::generate_random(),
	        public_sign_key : Random::generate_random(),
	        validation_token : Random::generate_random(),
	        name : Random::generate_random()
        }
	}
}

impl Random for SourceAddress {
	fn generate_random() -> SourceAddress {
		SourceAddress {
            from_node: Random::generate_random(),
            from_group: None,
            reply_to: None,
        }
	}
}


impl Random for messages::connect_request::ConnectRequest {
	fn generate_random() -> messages::connect_request::ConnectRequest {
		use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};
        

        // TODO: IPv6
        let random_addr = || -> SocketAddr {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>()),
                                             random::<u16>()))
        };

        messages::connect_request::ConnectRequest {
            local: random_addr(),
            external: random_addr(),
            requester_id: Random::generate_random(),
            receiver_id: Random::generate_random(),
            requester_fob: Random::generate_random(),
        }
	}	    
}


impl Random for messages::connect_response::ConnectResponse {
	fn generate_random() -> messages::connect_response::ConnectResponse {
        use std::net::{Ipv4Addr, SocketAddrV4, SocketAddr};        

        // TODO: IPv6
        let random_addr = || -> SocketAddr {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>(),
                                                           random::<u8>()),
                                            random::<u16>()))
        };

        messages::connect_response::ConnectResponse {
            requester_local: random_addr(),
            requester_external: random_addr(),
            receiver_local: random_addr(),
            receiver_external: random_addr(),
            requester_id: Random::generate_random(),
            receiver_id: Random::generate_random(),
            receiver_fob: Random::generate_random(),
        }
    }
}

impl Random for messages::connect_success::ConnectSuccess {
	fn generate_random() -> messages::connect_success::ConnectSuccess {
        messages::connect_success::ConnectSuccess {
            peer_id: Random::generate_random(),
            peer_fob: Random::generate_random(),
        }
    }
}

impl Random for messages::find_group::FindGroup {
	fn generate_random() -> messages::find_group::FindGroup {
        messages::find_group::FindGroup {
            requester_id: Random::generate_random(),
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::find_group_response::FindGroupResponse {
	fn generate_random() -> messages::find_group_response::FindGroupResponse {
        let total = GROUP_SIZE as usize + 20;
        let mut vec: Vec<PublicPmid> = Vec::with_capacity(total);
        for i in 0..total {
        	let public_pmid : PublicPmid = Random::generate_random();
            vec.push(public_pmid);
        }

        messages::find_group_response::FindGroupResponse {
            target_id: Random::generate_random(),
            group: vec,
        }
    }
}

impl Random for messages::get_client_key::GetClientKey {
	fn generate_random() -> messages::get_client_key::GetClientKey {
        messages::get_client_key::GetClientKey {
            requester_id: Random::generate_random(),
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_client_key_response::GetClientKeyResponse {
	fn generate_random() -> messages::get_client_key_response::GetClientKeyResponse {
        messages::get_client_key_response::GetClientKeyResponse {
            address: Random::generate_random(),
            public_sign_key: Random::generate_random(),
        }
    }
}

impl Random for messages::get_data::GetData {
	fn generate_random() -> messages::get_data::GetData {
        messages::get_data::GetData {
            requester: Random::generate_random(),
            name_and_type_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_data_response::GetDataResponse {
	fn generate_random() -> messages::get_data_response::GetDataResponse {
        messages::get_data_response::GetDataResponse {
            name_and_type_id: Random::generate_random(),
            data: generate_random_vec_u8(99),
            error: generate_random_vec_u8(99),
        }
    }
}


impl Random for messages::get_group_key::GetGroupKey {
	fn generate_random() -> messages::get_group_key::GetGroupKey {
        messages::get_group_key::GetGroupKey {
            requester: Random::generate_random(),
            target_id: Random::generate_random(),
        }
    }
}

impl Random for messages::get_group_key_response::GetGroupKeyResponse {
	fn generate_random() -> messages::get_group_key_response::GetGroupKeyResponse {
        let total: usize = GROUP_SIZE as usize + 7;
        let mut vec: Vec<(DhtId, PublicSignKey)> = Vec::with_capacity(total);
        for i in 0..total {
            vec.push((Random::generate_random(), Random::generate_random()));
        }
        messages::get_group_key_response::GetGroupKeyResponse {
            target_id: Random::generate_random(),
            public_sign_keys: vec,
        }
    }
}

impl Random for messages::post::Post {
	fn generate_random() -> messages::post::Post {
        messages::post::Post {
            name_and_type_id: Random::generate_random(),
            data: generate_random_vec_u8(99),
        }
    }
}

impl Random for messages::put_data::PutData {
	fn generate_random() -> messages::put_data::PutData {
        messages::put_data::PutData {
            name: generate_random_vec_u8(64),
            data: generate_random_vec_u8(99),
        }
    }
}

impl Random for messages::put_data_response::PutDataResponse {
	 fn generate_random() -> messages::put_data_response::PutDataResponse {
        messages::put_data_response::PutDataResponse {
            type_id: random::<u32>(),
            data: generate_random_vec_u8(99),
            error: generate_random_vec_u8(27),
        }
    }
}
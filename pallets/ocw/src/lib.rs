#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use frame_system::{
    self as system,
    ensure_signed,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendSignedTransaction, SendUnsignedTransaction,
        SignedPayload, Signer, SigningTypes, SubmitTransaction,
    },
};
use lite_json::json::JsonValue;
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
    offchain::{
        http,
        storage::{MutateStorageError, StorageRetrievalError, StorageValueRef},
        Duration,
    },
    traits::Zero,
    transaction_validity::{InvalidTransaction, TransactionValidity, ValidTransaction},
    RuntimeDebug,
};
use sp_io::offchain_index;
use sp_runtime::offchain::http::{Method, Request};
use sp_std::vec::Vec;
use serde::{Deserialize, Deserializer};
use serde_json::Value;


/// Defines application identifier for crypto keys of this module.
///
/// Every module that deals with signatures needs to declare its unique identifier for
/// its crypto keys.
/// When offchain worker is signing transactions it's going to request keys of type
/// `KeyTypeId` from the keystore and use the ones it finds to sign the transaction.
/// The keys can be inserted manually via RPC (see `author_insertKey`).
pub const KEY_TYPE: KeyTypeId = KeyTypeId(*b"btc!");
const ONCHAIN_TX_KEY: &[u8] = b"ocw::person_info";

/// Based on the above `KeyTypeId` we need to generate a pallet-specific crypto type wrappers.
/// We can use from supported crypto kinds (`sr25519`, `ed25519` and `ecdsa`) and augment
/// the types with this pallet-specific identifier.
pub mod crypto {
    use super::KEY_TYPE;
    use sp_core::sr25519::Signature as Sr25519Signature;
    use sp_runtime::{
        app_crypto::{app_crypto, sr25519},
        traits::Verify,
        MultiSignature, MultiSigner,
    };
    app_crypto!(sr25519, KEY_TYPE);

    pub struct TestAuthId;

    impl frame_system::offchain::AppCrypto<MultiSigner, MultiSignature> for TestAuthId {
        type RuntimeAppPublic = Public;
        type GenericPublic = sp_core::sr25519::Public;
        type GenericSignature = sp_core::sr25519::Signature;
    }

    // implemented for mock runtime in test
    impl frame_system::offchain::AppCrypto<<Sr25519Signature as Verify>::Signer, Sr25519Signature>
    for TestAuthId
    {
        type RuntimeAppPublic = Public;
        type GenericPublic = sp_core::sr25519::Public;
        type GenericSignature = sp_core::sr25519::Signature;
    }
}

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_support::StorageHasher;
    use frame_system::pallet_prelude::*;
    use sp_core::crypto::AccountId32;
    use sp_io::hashing::blake2_128;
    use sp_runtime::traits::{IdentifyAccount, Verify};
    use crate::crypto::Signature;

    /// This pallet's configuration trait
    #[pallet::config]
    pub trait Config: CreateSignedTransaction<Call<Self>> + frame_system::Config {
        /// The identifier type for an offchain worker.
        type AuthorityId: AppCrypto<Self::Public, Self::Signature>;

        /// The overarching event type.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;

        /// The overarching dispatch call type.
        type Call: From<Call<Self>>;

        // Configuration parameters
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn offchain_worker(block_number: T::BlockNumber) {
            log::info!("=================== OCW ====================");
            let key = Self::derived_key(block_number);
            let key = b"123".to_vec();
            log::info!("get key: {:#?}", &key);
            let storage_ref = StorageValueRef::persistent(&key);
            // storage_ref.set(&IndexingData(b"submit_number_unsigned".to_vec(), 7777));
            let r = storage_ref.get::<i32>();
            log::info!("r: {:#?}", &r);

            // if let Ok(Some(data)) = r {
            //     log::info!("local storage data: {:?}", data);
            // } else {
            //     log::info!("Error reading from local storage.");
            // }
        }
    }

    #[derive(Debug, Encode, Decode)]
    struct PersonInfoOcw {
        // 身份证号
        id_number: Vec<u8>,
        // 姓名
        name: Vec<u8>,
        // 电话号码
        phone: Vec<u8>,
    }

    #[derive(Debug, Deserialize, Encode, Decode, Default)]
    struct IndexingData(Vec<u8>, u64);

    /// A public part of the pallet.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        // register-mod
        #[pallet::weight(1_000)]
        pub fn submit_info(origin: OriginFor<T>,
                           id_number: Vec<u8>, name: Vec<u8>, phone: Vec<u8>) -> DispatchResult {
            log::info!("submit_info: {}, {}, {}",
				Self::v8_str(&id_number), Self::v8_str(&name), Self::v8_str(&phone));
            let who = ensure_signed(origin)?;
            log::info!("who: {:#?}", &who);
            let block_number: T::BlockNumber = frame_system::Module::<T>::block_number();
            let key = Self::derived_key(block_number);
            let key = b"123".to_vec();
            log::info!("set key: {:#?}", &key);
            let data = 666;
            let q = offchain_index::set(&key, &data.encode());
            log::info!("q: {:#?}", q);
            Ok(())
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Event generated when new price is accepted to contribute to the average.
        NewPrice { price: u32, who: T::AccountId },
    }

    /// register-mod
    /// todo 看是否要切换为map,
    #[pallet::storage]
    #[pallet::getter(fn ids_owned)]
    /// Keeps track of what accounts own what id.
    pub(super) type IdsOwned<T: Config> = StorageMap<
        _,
        Twox64Concat,
        T::AccountId,
        Vec<u8>,
        ValueQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn persons)]
    pub(super) type PersonInfo<T: Config> = StorageValue<_, Vec<u8>, OptionQuery>;
}


impl<T: Config> Pallet<T> {
    /// 验证三要素匹配
    fn validate_info(id_number: &Vec<u8>, name: &Vec<u8>, phone: &Vec<u8>) -> Result<u32, http::Error> {
        let deadline = sp_io::offchain::timestamp().add(Duration::from_millis(2_000));
        let mut params = Vec::new();
        params.push("idcard=".as_bytes());
        params.push(&id_number);
        params.push("&mobile=".as_bytes());
        params.push(&phone);
        params.push("&name=".as_bytes());
        params.push(&name);
        let request =
            http::Request::post("http://sjsys.market.alicloudapi.com/communication/personal/1979",
                                params);
        let pending = request
            .add_header("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
            .add_header("Authorization", "APPCODE ae1e3033a5de4969a3239250096c9cae")
            .deadline(deadline).send().map_err(|_| http::Error::IoError)?;

        let response = pending.try_wait(deadline).map_err(|_| http::Error::DeadlineReached)??;
        if response.code != 200 {
            log::warn!("Unexpected status code: {}", response.code);
        }

        let body = response.body().collect::<Vec<u8>>();
        log::info!("body: {}", Self::v8_str(&body));
        let body_str = sp_std::str::from_utf8(&body).map_err(|_| {
            log::warn!("No UTF8 body");
            http::Error::Unknown
        })?;
        let state = Self::parse_state(body_str);
        if let Some(sate) = state.as_str() {
            log::info!("{}", state);
        } else {
            log::error!("api error");
        }
        Ok(1)
    }

    // register-mod
    fn parse_state(resp_str: &str) -> Value {
        let mut json_data: Value = serde_json::from_str(resp_str).unwrap();
        json_data["data"]["state"].take()
    }
    fn v8_str(vec: &Vec<u8>) -> &str {
        sp_std::str::from_utf8(vec).unwrap()
    }
    fn derived_key(block_number: T::BlockNumber) -> Vec<u8> {
        block_number.using_encoded(|encoded_bn| {
            ONCHAIN_TX_KEY.clone().into_iter()
                .chain(b"/".into_iter())
                .chain(encoded_bn)
                .copied()
                .collect::<Vec<u8>>()
        })
    }
}
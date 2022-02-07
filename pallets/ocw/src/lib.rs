#![cfg_attr(not(feature = "std"), no_std)]

mod sp_merkle;

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
use sp_std::collections::{btree_map::BTreeMap, vec_deque::VecDeque};
use sp_io::hashing::twox_64;


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
use crate::sp_merkle::MerkleTree;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_support::sp_core_hashing_proc_macro::twox_64;
    use frame_support::StorageHasher;
    use frame_system::pallet_prelude::*;
    use sp_core::crypto::AccountId32;
    use sp_io::hashing::blake2_128;
    use sp_runtime::traits::{IdentifyAccount, Verify};
    use crate::crypto::Signature;
    use crate::Event::SubmitInfo;

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
            log::info!("=================== OCW VALIDATE BLOCK ====================");
            let keys = <BlockKeys<T>>::get(block_number);
            // Self::append_key(block_number, Vec::new());
            log::info!("\nget: {:?}, {:?}\n", block_number, keys);
            if keys.is_empty() {
                // 如果没有录入, 结束
                return;
            }
            for key in keys {
                let storage_ref = StorageValueRef::persistent(&key);
                if let Ok(Some(data)) = storage_ref.get::<PersonInfoOcw>() {
                    log::info!("local storage data: {:?}", data);
                    let owner =
                        T::AccountId::decode(&mut &*data.owner).unwrap();
                    let id_no = data.id_number.clone();
                    let res =
                        Self::validate_info(&data.id_number, &data.name, &data.phone);
                    if let Ok(state) = res {
                        log::info!("validate: {} id: {:?}", state, &data.id_number);
                        if state == 1 {
                            // 验证通过
                            let tree = Self::build_age_merkle(&id_no[6..10]);
                            let to_validate = twox_64("2004:1".as_ref()).to_vec();
                            let path = tree.merkle_path(&to_validate);
                            let result = MerkleTree::verify_data(&to_validate, &path,
                                                                 &tree.root_hash);
                            log::info!("result: {}", result);
                        }
                    }
                }
            }
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
        // 持有人
        owner: Vec<u8>,
    }

    /// A public part of the pallet.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(1_000)]
        pub fn submit_info(origin: OriginFor<T>,
                           id_number: Vec<u8>, name: Vec<u8>, phone: Vec<u8>) -> DispatchResult {
            log::info!("submit_info: {}, {}, {}",
				Self::v8_str(&id_number), Self::v8_str(&name), Self::v8_str(&phone));
            let who = ensure_signed(origin)?;
            log::info!("who: {:#?}", &who);
            let block_number: T::BlockNumber = frame_system::Pallet::<T>::block_number();
            let key = Self::derived_key(block_number, who.clone());
            let data = PersonInfoOcw {
                id_number,
                name,
                phone,
                owner: who.encode(),
            };
            Self::append_key(block_number, key.clone());
            offchain_index::set(&key, &data.encode());
            Self::deposit_event(SubmitInfo { who });
            Ok(())
        }

        #[pallet::weight(1_0000)]
        pub fn grant_id(origin: OriginFor<T>, id_tree: Vec<u8>, owner: T::AccountId) -> DispatchResult {
            let who = ensure_signed(origin)?;
            todo!("verify who");
            <IdsOwned<T>>::mutate(&owner, |id_merkle| {
                <IdsOwned<T>>::insert(owner.clone(), id_tree);
            });
            Ok(())
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        SubmitInfo { who: T::AccountId }
    }

    /// register-mod
    #[pallet::storage]
    #[pallet::getter(fn ids_owned)]
    /// Keeps track of what accounts own what age merkle.
    pub(super) type IdsOwned<T: Config> = StorageMap<
        _,
        Twox128,
        T::AccountId,
        Vec<u8>,
        OptionQuery,
    >;

    #[pallet::storage]
    #[pallet::getter(fn block_keys)]
    // key: 块, val: 当前块生成的key
    pub(super) type BlockKeys<T: Config> = StorageMap<
        _,
        Twox64Concat,
        T::BlockNumber,
        VecDeque<Vec<u8>>,
        ValueQuery
    >;
}


impl<T: Config> Pallet<T> {
    /// 验证某块中所有用户数据
    fn ocw_validate_block(block_number: T::BlockNumber) {
        // log::info!("=================== OCW VALIDATE BLOCK ====================");
        // let keys = <BlockKeys<T>>::get(block_number);
        // // Self::append_key(block_number, Vec::new());
        // log::info!("\nget: {:?}, {:?}\n", block_number, keys);
        // if keys.is_empty() {
        //     // 如果没有录入, 结束
        //     return;
        // }
        // for key in keys {
        //     let storage_ref = StorageValueRef::persistent(&key);
        //     if let Ok(Some(data)) = storage_ref.get::<PersonInfoOcw>() {
        //         log::info!("local storage data: {:?}", data);
        //         let owner =
        //             T::AccountId::decode(&mut &*data.owner).unwrap();
        //         let id_no = data.id_number.clone();
        //         let res =
        //             Self::validate_info(&data.id_number, &data.name, &data.phone);
        //         if let Ok(state) = res {
        //             log::info!("validate: {} id: {:?}", state, &data.id_number);
        //             if state == 1 {
        //                 // 验证通过
        //                 let tree = Self::build_age_merkle(&id_no[6..10]);
        //                 let to_validate = twox_64("2004:1".as_ref()).to_vec();
        //                 let path = tree.merkle_path(&to_validate);
        //                 let result = MerkleTree::verify_data(&to_validate, &path,
        //                                                      &MerkleTree::unwrap(&tree.tree_root).hash);
        //                 log::info!("result: {}", result);
        //             }
        //         }
        //     }
        // }
    }
    /// 验证三要素匹配
    fn validate_info(id_number: &Vec<u8>, name: &Vec<u8>, phone: &Vec<u8>) -> Result<i32, http::Error> {
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
        let state_val = Self::parse_state(body_str);
        return if let Some(state) = state_val.as_str() {
            log::info!("{}", state);
            Ok(str::parse::<i32>(state).unwrap())
        } else {
            log::error!("api error");
            Ok(-1)
        };
    }

    fn build_age_merkle(birth: &[u8]) -> MerkleTree {
        let mut data = Vec::new();
        // 构建范围数据，前后一百年 1900-2100
        for year in 1900..=2100 {
            let to_add_data = Self::format_u8_data(birth, year);
            data.push(twox_64(to_add_data.as_ref()).to_vec());
        }
        MerkleTree::build(&data)
    }

    /// 四位数字转为Vec<u8>
    fn format_u8_data(birth: &[u8], year: u32) -> Vec<u8> {
        // year 转 u8
        let mut year_u8 = Vec::new();
        year_u8.push((year / 1000 + 48) as u8);
        year_u8.push(((year % 1000) / 100 + 48) as u8);
        year_u8.push(((year % 100) / 10 + 48) as u8);
        year_u8.push(((year % 10) / 1 + 48) as u8);
        // 组装格式 year:birthed
        let mut data: Vec<u8> = Vec::new();
        data.append(&mut year_u8.clone());
        data.push(58);
        if year_u8 >= birth.to_vec() {
            data.push(49);
        } else {
            data.push(48);
        }
        data
    }

    fn append_key(block_number: T::BlockNumber, key: Vec<u8>) {
        <BlockKeys<T>>::mutate(block_number, |keys| {
            keys.push_back(key);
            log::info!("\nBlock keys: {:?}, block_number: {:?}\n", keys, block_number);
        });
    }

    fn parse_state(resp_str: &str) -> Value {
        let mut json_data: Value = serde_json::from_str(resp_str).unwrap();
        json_data["data"]["state"].take()
    }
    fn v8_str(vec: &Vec<u8>) -> &str {
        sp_std::str::from_utf8(vec).unwrap()
    }

    fn derived_key(block_number: T::BlockNumber, account_id: T::AccountId) -> Vec<u8> {
        block_number.using_encoded(|encoded_bn| {
            ONCHAIN_TX_KEY.clone().into_iter()
                .chain(b"/".into_iter())
                .chain(encoded_bn)
                .chain(b"/".into_iter())
                .chain(account_id.encode().as_slice().into_iter())
                .copied()
                .collect::<Vec<u8>>()
        })
    }
}
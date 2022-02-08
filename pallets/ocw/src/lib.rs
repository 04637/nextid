#![cfg_attr(not(feature = "std"), no_std)]

mod sp_merkle;

use codec::{Decode, Encode};
use frame_system::{
    ensure_signed,
    ensure_root,
    offchain::{
        AppCrypto, CreateSignedTransaction, SendSignedTransaction, Signer,
    },
};
use sp_core::crypto::KeyTypeId;
use sp_runtime::{
    offchain::{
        http,
        storage::{StorageValueRef},
        Duration,
    },
};
use sp_io::offchain_index;
use sp_std::vec::Vec;
use serde_json::Value;
use sp_std::collections::{vec_deque::VecDeque};
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
    use frame_system::pallet_prelude::*;
    use sp_runtime::traits::{BadOrigin};
    use crate::Event::*;

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
            log::info!("=================== OCW VALIDATE BLOCK ====================");
            // 验证块中信息
            Self::ocw_validate_block(&block_number);
        }
    }

    /// A public part of the pallet.
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// # 提交身份信息
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

        /// # 颁发ID
        /// 不可用ensure_root限制, https://stackoverflow.com/questions/63756597/is-it-possible-for-an-offchain-worker-to-submit-calls-to-an-extrinsic-with-ensur
        /// call from ocw
        #[pallet::weight(1_000_000_000)]
        pub fn grant_id(_origin: OriginFor<T>, age_tree: Vec<u8>, owner: T::AccountId, password: Vec<u8>) -> DispatchResult {
            ensure!(password == b"ocw".to_vec(), Error::<T>::OffchainSignedTxError);
            // verify root
            // `Sudo` pallet https://docs.substrate.io/rustdocs/master/pallet_sudo/index.html
            // `Origin` type https://docs.substrate.io/v3/runtime/origins/
            let block_number: T::BlockNumber = frame_system::Pallet::<T>::block_number();
            <IdsOwned<T>>::insert(owner.clone(), age_tree);
            log::info!("Verified!, owner: {:?}, block_number: {:?}", &owner, block_number);
            Self::deposit_event(GrantId { who: owner });
            Ok(())
        }

        /// # root 添加可检查ID的账户
        #[pallet::weight(0)]
        pub fn auth_check_account(origin: OriginFor<T>, account: T::AccountId) -> DispatchResult {
            ensure_root(origin)?;
            Self::add_check_account(account.clone());
            Self::deposit_event(AuthAccount { who: account });
            Ok(())
        }

        /// # 企业用户检查用户年龄
        #[pallet::weight(1_000)]
        pub fn limit_account_year(origin: OriginFor<T>, account: T::AccountId, mut year: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            if Self::can_check_account(&who) {
                let merkle_u8 = <IdsOwned<T>>::get(&account);
                ensure!(merkle_u8!=None, Error::<T>::NotVerifiedAccount);
                return if let Ok(merkle) = MerkleTree::decode(&mut &*merkle_u8.unwrap()) {
                    let mut to_validate_data = Vec::new();
                    to_validate_data.append(&mut year);
                    to_validate_data.append(&mut b":1".to_vec());
                    let to_validate = twox_64(&*to_validate_data).to_vec();
                    let path = merkle.merkle_path(&to_validate);
                    let result = MerkleTree::check_data(&to_validate, &path,
                                                        &merkle.root_hash);
                    ensure!(result, Error::<T>::NotSatisfiedLimit);
                    Ok(())
                } else {
                    Err(DispatchError::from(BadOrigin))
                };
            }
            Err(DispatchError::from(BadOrigin))
        }
    }

    /// Events for the pallet.
    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        SubmitInfo { who: T::AccountId },
        GrantId { who: T::AccountId },
        AuthAccount { who: T::AccountId },
        CheckAccount { from_account: T::AccountId, to_account: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        // ocw签名失败
        OffchainSignedTxError,
        // 没有本地账户
        NoLocalAcctForSigning,
        // 账户还未实名
        NotVerifiedAccount,
        // 账户无权检查
        CanNotCheckAccount,
        // 验证无效
        NotSatisfiedLimit,
    }

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

    #[pallet::storage]
    // 可以检查身份的账户
    pub(super) type CanCheckAccounts<T: Config> = StorageValue<_, Vec<T::AccountId>, ValueQuery>;

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

    impl<T: Config> Pallet<T> {
        /// 验证某块中用户数据
        fn ocw_validate_block(block_number: &T::BlockNumber) {
            let keys = <BlockKeys<T>>::get(block_number);
            log::info!("\nblock: {:?},\nkeys:{:?}\n", block_number, keys);
            if keys.is_empty() {
                // 如果没有录入, 结束
                return;
            }
            for key in keys {
                let storage_ref = StorageValueRef::persistent(&key);
                if let Ok(Some(data)) = storage_ref.get::<PersonInfoOcw>() {
                    log::debug!("cur_data: {:?}", data);
                    let owner =
                        T::AccountId::decode(&mut &*data.owner).unwrap();
                    let id_no = data.id_number.clone();
                    let res =
                        Self::validate_info(&data.id_number, &data.name, &data.phone);
                    if let Ok(state) = res {
                        log::info!("validate: {} id: {}", state, Self::v8_str(&data.id_number));
                        if state == 1 {
                            // 验证通过
                            let tree = Self::build_age_merkle(&id_no[6..10]);
                            // 签名上链
                            let _ = Self::ocw_signed_tx(tree.encode(), owner);
                        } else {
                            // 验证失败
                        }
                    }
                }
            }
        }

        /// 添加可检查身份的账号
        fn add_check_account(who: T::AccountId) {
            if !Self::can_check_account(&who) {
                log::info!("Adding account to checkAccounts: {:?}", &who);
                <CanCheckAccounts<T>>::mutate(|accounts| {
                    accounts.push(who);
                });
            }
        }

        /// 检查账户有没有检查权限
        fn can_check_account(who: &T::AccountId) -> bool {
            <CanCheckAccounts<T>>::get().into_iter().
                find(|a| a == who).is_some()
        }


        fn ocw_signed_tx(age_tree: Vec<u8>, owner: T::AccountId) -> Result<(), Error<T>> {
            // We retrieve a signer and check if it is valid.
            //   Since this pallet only has one key in the keystore. We use `any_account()1 to
            //   retrieve it. If there are multiple keys and we want to pinpoint it, `with_filter()` can be chained,
            //   ref: https://substrate.dev/rustdocs/v3.0.0/frame_system/offchain/struct.Signer.html
            let signer = Signer::<T, T::AuthorityId>::any_account();
            // `result` is in the type of `Option<(Account<T>, Result<(), ()>)>`. It is:
            //   - `None`: no account is available for sending transaction
            //   - `Some((account, Ok(())))`: transaction is successfully sent
            //   - `Some((account, Err(())))`: error occured when sending the transaction
            let result = signer.send_signed_transaction(|_account|
                //This means that the transaction, when executed, will simply call that
                // function passing `price` as an argument.
                Call::grant_id {
                    age_tree: age_tree.clone(),
                    owner: owner.clone(),
                    password: b"ocw".to_vec(),
                }
            );

            // Display error if the signed tx fails.
            if let Some((acc, res)) = result {
                if res.is_err() {
                    log::error!("failure: offchain_signed_tx, tx sent: {:?}", acc.id);
                    return Err(<Error<T>>::OffchainSignedTxError);
                }
                // Transaction is sent successfully
                Ok(())
            } else {
                // The case result == `None`: no account is available for sending
                log::error!("No local account available");
                Err(<Error<T>>::NoLocalAcctForSigning)
            }
        }

        /// 验证三要素匹配
        fn validate_info(id_number: &Vec<u8>, name: &Vec<u8>, phone: &Vec<u8>) -> Result<i32, http::Error> {
            // return Ok(1);
            // 14272419960206331X, %E7%B1%8D%E8%A7%82%E9%80%9A, 18652030106
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
                data.push(to_add_data);
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

        /// 从校验api中解析验证结果
        fn parse_state(resp_str: &str) -> Value {
            let mut json_data: Value = serde_json::from_str(resp_str).unwrap();
            json_data["data"]["state"].take()
        }
        fn v8_str(vec: &Vec<u8>) -> &str {
            sp_std::str::from_utf8(vec).unwrap()
        }

        /// 生成key
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
}
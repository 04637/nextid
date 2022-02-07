#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::borrow::Borrow;
use sp_std::cell::{Ref, RefCell};
use sp_std::fmt::{Display, Formatter};
use sp_std::hash::{Hash};
use sp_std::rc::Rc;
use sp_std::vec::Vec;
use sp_io::hashing::twox_64;
use sp_std::collections::btree_map::BTreeMap;
use sp_core::{Encode, Decode};

pub struct MerkleTree {
    pub tree_root: TreeNodeType,
    // key: hash of [year:1or0] val: node
    pub tree_leaf: BTreeMap<Vec<u8>, TreeNodeType>,
}

type TreeNodeType = Rc<RefCell<TreeNode>>;

#[derive(Encode, Decode)]
pub struct TreeNode {
    // 哈希值
    pub hash: Vec<u8>,
    pub left: Option<TreeNodeType>,
    pub right: Option<TreeNodeType>,
    pub parent: Option<TreeNodeType>,
    pub is_left: bool,
}

// #[cfg(feature = "std")]
impl Display for TreeNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> sp_std::fmt::Result {
        let mut left_hash = Vec::new();
        let mut right_hash = Vec::new();
        let mut parent_hash = Vec::new();

        if let Some(left) = &self.left {
            left_hash = MerkleTree::unwrap(left).hash.clone();
        }
        if let Some(right) = self.right.as_ref() {
            right_hash = MerkleTree::unwrap(right).hash.clone()
        }
        if let Some(parent) = self.parent.as_ref() {
            parent_hash = MerkleTree::unwrap(parent).hash.clone();
        }
        write!(f, "hash: {:?}, isLeft: {}
        left: {:?},
        right: {:?},
        parent: {:?}\n",
               self.hash,
               self.is_left,
               left_hash,
               right_hash,
               parent_hash
        )
    }
}

impl MerkleTree {
    // 数据hash => 默克尔树
    pub fn build(data_hash: &Vec<Vec<u8>>) -> MerkleTree {
        let mut data_vec = Vec::new();
        let mut tree_leaf = BTreeMap::new();
        for (i, val) in data_hash.iter().enumerate() {
            let tree_data =
                Rc::new(RefCell::new(Self::new_data_node(
                    val.clone()
                )));
            data_vec.push(Rc::clone(&tree_data));
            tree_leaf.insert(val.clone(), Rc::clone(&tree_data));
        }
        let tree_root = Self::build_from_vec_recur(data_vec).pop().unwrap();
        MerkleTree {
            tree_root,
            tree_leaf,
        }
    }

    // 多节点自下而上递归构建默克尔树
    fn build_from_vec_recur(vec: Vec<TreeNodeType>) -> Vec<TreeNodeType> {
        let mut last = None;
        let mut tree_vec = Vec::new();
        if vec.len() <= 1 {
            return vec;
        }
        for x in vec {
            // 查看是否有上一个节点
            match last.take() {
                // 如果已有上一个节点, 则组树
                Some(last_tree) => {
                    let parent = Self::combine_node(Rc::clone(&last_tree),
                                                    Rc::clone(&x));
                    log::debug!("{}", Self::unwrap(&last_tree));
                    log::debug!("{}", Self::unwrap(&x));
                    tree_vec.push(parent);
                }
                None => {
                    last = Some(Rc::clone(&x));
                }
            }
        }
        // 结束时last没上树
        if let Some(last_tree) = last {
            log::debug!("{}", Self::unwrap(&last_tree));
            tree_vec.push(Rc::from(last_tree));
        }
        log::debug!("================================================================");
        Self::build_from_vec_recur(tree_vec)
    }

    // 两节点组合为一个
    fn combine_node(left: TreeNodeType, right: TreeNodeType) -> TreeNodeType {
        let parent;
        {
            let left_ref = Self::unwrap(&left);
            let right_ref = Self::unwrap(&right);
            let mut to_hash = Vec::new();
            to_hash.append(&mut left_ref.hash.clone());
            to_hash.append(&mut right_ref.hash.clone());
            let hashed = twox_64(&*to_hash);
            let hash_vec: Vec<u8> = hashed.to_vec();
            parent = Rc::new(RefCell::new(Self::new_tree_node(hash_vec,
                                                              Some(Rc::clone(&left)),
                                                              Some(Rc::clone(&right)))));
        }
        (*left).borrow_mut().parent = Some(Rc::clone(&parent));
        (*left).borrow_mut().is_left = true;
        (*right).borrow_mut().parent = Some(Rc::clone(&parent));
        (*right).borrow_mut().is_left = false;
        parent
    }

    fn new_data_node(hash: Vec<u8>) -> TreeNode {
        TreeNode {
            hash,
            left: None,
            right: None,
            parent: None,
            is_left: true,
        }
    }

    fn new_tree_node(hash: Vec<u8>,
                     left: Option<TreeNodeType>,
                     right: Option<TreeNodeType>) -> TreeNode {
        TreeNode {
            hash,
            left,
            right,
            parent: None,
            is_left: true,
        }
    }

    // 解包
    pub(crate) fn unwrap(wrapped: &TreeNodeType) -> Ref<TreeNode> {
        Ref::map(
            (**wrapped).borrow(),
            |borrowed| { &(*borrowed) },
        )
    }
}

impl MerkleTree {
    /// # 根据交易序号获取默克尔路径
    /// log2(n)个节点, 寻找默克尔路径
    ///
    /// * `data_hash` - 数据hash
    /// return (node_hash, is_left)
    pub fn merkle_path(&self, data_hash: &Vec<u8>) -> Vec<(Vec<u8>, bool)> {
        let mut path: Vec<(Vec<u8>, bool)> = Vec::new();
        let data_node = &self.tree_leaf.get(&*data_hash);
        if let Some(data_node) = data_node {
            Self::recur_upward(data_node, &mut path);
        }
        path
    }

    /// # 根据默克尔路径验证数据
    /// * `data` - 待验证原始数据
    /// * `path` - 默克尔路径 `vec![hash1, hash2]`
    /// * `root_hash` - 根hash
    pub fn verify_data(data_hash: &Vec<u8>, path: &Vec<(Vec<u8>, bool)>, root_hash: &Vec<u8>) -> bool {
        let mut data_hash = data_hash.clone();
        for (path_hash, is_left) in path {
            if !is_left {
                data_hash.append(&mut path_hash.clone());
                data_hash = Vec::from(twox_64(&*data_hash));
            } else {
                let mut path_hash = path_hash.clone();
                path_hash.append(&mut data_hash.clone());
                data_hash = Vec::from(twox_64(&*path_hash));
            }
            log::debug!("verify_data: {:?}", data_hash);
        }
        &data_hash == root_hash
    }

    /// 向上递归, 找兄弟节点
    fn recur_upward(tree_node: &TreeNodeType, path: &mut Vec<(Vec<u8>, bool)>) {
        let unwrap_cur = MerkleTree::unwrap(tree_node);
        let parent = &unwrap_cur.parent;
        if let Some(parent) = parent {
            // 有父节点, 留下兄弟节点, 继续向上
            if unwrap_cur.is_left {
                if let Some(right_node) = &MerkleTree::unwrap(parent).right {
                    let unwrap_right = MerkleTree::unwrap(right_node);
                    path.push((unwrap_right.hash.clone(), false));
                }
            } else {
                if let Some(left_node) = &MerkleTree::unwrap(parent).left {
                    let unwrap_left = MerkleTree::unwrap(left_node);
                    path.push((unwrap_left.hash.clone(), true));
                }
            }
            Self::recur_upward(&Rc::clone(parent), path);
        } else {
            return;
        }
    }
}

#[test]
fn test() {
    let mut data = Vec::new();
    data.push(twox_64(&*b"vec1".to_vec()).to_vec());
    data.push(twox_64(&*b"vec2".to_vec()).to_vec());
    data.push(twox_64(&*b"vec3".to_vec()).to_vec());
    data.push(twox_64(&*b"vec4".to_vec()).to_vec());
    data.push(twox_64(&*b"vec5".to_vec()).to_vec());
    data.push(twox_64(&*b"vec6".to_vec()).to_vec());

    let v = MerkleTree::build(&data);
    // log::debug!("{}", (*v.tree_root).borrow());
    // log::debug!("{}", (*v.tree_leaf).borrow().len());
    let path = v.merkle_path(&twox_64(&*b"vec3".to_vec()).to_vec());
    for x in &path {
        log::debug!("merkle_path: {:?}: {}", x.0, &x.1);
    }
    // let path: Vec<Vec<u8>> = path.into_iter().map(
    //     |v| v.1
    // ).collect::<Vec<Vec<u8>>>();
    let result = MerkleTree::verify_data(&twox_64(&*b"vec3".to_vec()).to_vec(), &path,
                                         &MerkleTree::unwrap(&v.tree_root).hash);
    log::debug!("result: {}", result);
}

#[test]
fn test_build_age() {
    let mut data = Vec::new();
    // 26岁 1996年生
    let birth = 1996;
    let limit_age = 18;
    // 2022-18 2004:1
    let to_validate_data_hash = twox_64("2004:1".as_ref()).to_vec();

    // 构建范围数据，前后一百年 1900-2100
    for year in 1900..=2100 {
        log::debug!("{}", year);
        let mut birthed = "0";
        if year >= birth {
            birthed = "1";
        }
        let to_add_data = year.to_string() + ":" + birthed;
        data.push(twox_64(to_add_data.as_ref()).to_vec());
    }
    let v = MerkleTree::build(&data);
    let path = v.merkle_path(&to_validate_data_hash);
    for x in &path {
        log::debug!("merkle_path: {:?}: {}", x.0, &x.1);
    }
    let result = MerkleTree::verify_data(&to_validate_data_hash, &path,
                                         &MerkleTree::unwrap(&v.tree_root).hash);
    log::debug!("result: {}", result);
}

#[test]
fn test_vec_str() {
    let mut q = "0123456789:".as_bytes().into_iter()
        // .chain(b"1996".into_iter())
        .copied().collect::<Vec<u8>>();
    log::debug!("{:?}, {}", q, sp_std::str::from_utf8(&q).unwrap());
}

#[test]
fn format_u8_data() {
    // let mut data: Vec<u8> = Vec::new();
    // let birth = 1996u32;
    // data.push((year / 1000 + 48) as u8);
    // data.push(((year%1000) / 100 + 48) as u8);
    // data.push(((year%100) / 10 + 48) as u8);
    // data.push(((year%10) / 1 + 48) as u8);

    let year = 1993u32;
    let birth = b"1996".to_vec();
    let mut year_u8 = Vec::new();
    year_u8.push((year / 1000 + 48) as u8);
    year_u8.push(((year % 1000) / 100 + 48) as u8);
    year_u8.push(((year % 100) / 10 + 48) as u8);
    year_u8.push(((year % 10) / 1 + 48) as u8);
    let mut data: Vec<u8> = Vec::new();
    data.append(&mut year_u8.clone());
    data.push(58);
    if year_u8 >= birth {
        data.push(49);
    } else {
        data.push(48);
    }
    println!("data: {}", sp_std::str::from_utf8(&data).unwrap());
}
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

#[derive(Encode, Decode)]
pub struct MerkleTree {
    pub root_hash: Vec<u8>,
    // key: hash  val: node
    pub nodes: BTreeMap<Vec<u8>, TreeNode>,
}


#[derive(Encode, Decode, Clone)]
pub struct TreeNode {
    // 哈希值
    pub hash: Vec<u8>,
    // 左节点hash
    pub left: Vec<u8>,
    // 右节点hash
    pub right: Vec<u8>,
    // 父节点hash
    pub parent: Vec<u8>,
    // 是否是左子树
    pub is_left: bool,
}

// #[cfg(feature = "std")]
impl Display for TreeNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> sp_std::fmt::Result {
        write!(f, "hash: {:?}, isLeft: {}
        left: {:?},
        right: {:?},
        parent: {:?}\n",
               self.hash,
               self.is_left,
               self.left,
               self.right,
               self.parent,
        )
    }
}

/// impl methods for merkle.
impl MerkleTree {
    // 原始数据vec => 默克尔树
    pub fn build(data_hash: &Vec<Vec<u8>>) -> MerkleTree {
        // 初始化一个树
        let mut merkle = Self::new();
        let mut to_recur = Vec::new();
        for data in data_hash {
            let new_node = merkle.new_data_node(data);
            to_recur.push(new_node.clone());
        }
        // 复制叶子节点, 构建树
        // let mut to_recur: Vec<TreeNode> = merkle.nodes.values().cloned().collect();
        // 自下而上构建默克尔树
        let tree_root = merkle.build_from_vec_recur(to_recur).pop().unwrap();
        merkle.root_hash = tree_root.hash;
        merkle
    }

    // 多节点自下而上递归构建默克尔树
    fn build_from_vec_recur(&mut self, vec: Vec<TreeNode>) -> Vec<TreeNode> {
        let mut last: Option<TreeNode> = None;
        let mut tree_vec = Vec::new();
        if vec.len() <= 1 {
            return vec;
        }
        for x in vec {
            // 查看是否有上一个节点
            match last.take() {
                // 如果已有上一个节点, 则组树
                Some(last_node) => {
                    let parent = self.combine_node(last_node.clone(),
                                                   x.clone());
                    // println!("{}", self.get_node(&last_node.hash).unwrap());
                    // println!("{}", self.get_node(&x.hash).unwrap());
                    tree_vec.push(parent.clone());
                }
                None => {
                    last = Some(x.clone());
                }
            }
        }
        // 结束时last没上树
        if let Some(last_node) = last {
            // println!("{}", &last_node);
            tree_vec.push(last_node);
        }
        // println!("================================================================");
        self.build_from_vec_recur(tree_vec)
    }

    // 两节点组合为一个
    fn combine_node(&mut self, left: TreeNode, right: TreeNode) -> TreeNode {
        // 计算合并hash
        let mut to_hash = Vec::new();
        to_hash.append(&mut left.hash.clone());
        to_hash.append(&mut right.hash.clone());
        let hash_vec = twox_64(&*to_hash).to_vec();
        let parent = self.new_node(hash_vec, left.hash.clone(),
                                   right.hash.clone());
        self.set_parent(&left.hash, &parent.hash);
        self.set_is_left(&left.hash, true);
        self.set_parent(&right.hash, &parent.hash);
        self.set_is_left(&right.hash, false);
        parent
    }
}

/// impl validate func for merkle
impl MerkleTree {
    /// # 根据数据hash获取默克尔路径
    /// log2(n)个节点, 寻找默克尔路径
    ///
    /// * `data_hash` - 数据hash
    /// return (node_hash, is_left)
    pub fn merkle_path(&self, data_hash: &Vec<u8>) -> Vec<(Vec<u8>, bool)> {
        let mut path: Vec<(Vec<u8>, bool)> = Vec::new();
        let node = self.get_node(data_hash);
        if let Some(data_node) = node {
            self.recur_upward(&data_node.hash, &mut path);
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
            // println!("verify_data: {:?}", data_hash);
        }
        &data_hash == root_hash
    }

    /// 向上递归, 找兄弟节点
    fn recur_upward(&self, cur_node_hash: &Vec<u8>, path: &mut Vec<(Vec<u8>, bool)>) {
        // println!("cur_hash: {:?}", cur_node_hash);
        let parent = self.parent(cur_node_hash);
        if let Some(parent) = parent {
            // 有父节点, 留下兄弟节点, 继续向上
            if self.get_node(cur_node_hash).unwrap().is_left {
                if let Some(right_node) = self.right(&parent.hash) {
                    path.push((right_node.hash.clone(), false));
                }
            } else {
                if let Some(left_node) = self.left(&parent.hash) {
                    path.push((left_node.hash.clone(), true));
                }
            }
            self.recur_upward(&parent.hash, path);
        } else {
            return;
        }
    }
}

impl MerkleTree {
    // 根据hash获取节点
    pub fn get_node(&self, hash: &Vec<u8>) -> Option<TreeNode> {
        if let Some(node) = self.nodes.get(hash) {
            return Some(node.clone());
        }
        None
    }

    // 获取对应hash的左节点
    fn left(&self, hash: &Vec<u8>) -> Option<TreeNode> {
        let node = self.get_node(hash);
        if let Some(node) = node {
            return self.get_node(&node.left);
        }
        None
    }

    // 设置左节点
    fn set_left(&mut self, hash: &Vec<u8>, left_hash: &Vec<u8>) {
        let node = self.get_node(hash);
        if let Some(node) = node {
            let mut node = node.clone();
            node.left = left_hash.clone();
            self.nodes.insert(hash.clone(), node);
        }
    }

    // 获取对应hash的右节点
    fn right(&self, hash: &Vec<u8>) -> Option<TreeNode> {
        let node = self.get_node(hash);
        if let Some(node) = node {
            return self.get_node(&node.right);
        }
        None
    }

    // 设置右节点
    fn set_right(&mut self, hash: &Vec<u8>, right_hash: &Vec<u8>) {
        let node = self.get_node(hash);
        if let Some(node) = node {
            let mut node = node.clone();
            node.right = right_hash.clone();
            self.nodes.insert(hash.clone(), node);
        }
    }

    // 获取对应hash的父节点
    fn parent(&self, hash: &Vec<u8>) -> Option<TreeNode> {
        let node = self.get_node(hash);
        if let Some(node) = node {
            return self.get_node(&node.parent);
        }
        None
    }

    // 设置父节点
    fn set_parent(&mut self, hash: &Vec<u8>, parent_hash: &Vec<u8>) {
        let node = self.get_node(hash);
        if let Some(node) = node {
            let mut node = node.clone();
            node.parent = parent_hash.clone();
            self.nodes.insert(hash.clone(), node);
        }
    }

    // 设置是否左子树
    fn set_is_left(&mut self, hash: &Vec<u8>, is_left: bool) {
        let node = self.get_node(hash);
        if let Some(node) = node {
            let mut node = node.clone();
            node.is_left = is_left;
            self.nodes.insert(hash.clone(), node);
        }
    }


    fn new_data_node(&mut self, data: &Vec<u8>) -> TreeNode {
        let data_hash = twox_64(&*data).to_vec();
        self.new_node(data_hash, Vec::new(), Vec::new())
    }

    fn new_node(&mut self, node_hash: Vec<u8>,
                left: Vec<u8>,
                right: Vec<u8>) -> TreeNode {
        let node = TreeNode {
            hash: node_hash.clone(),
            left,
            right,
            parent: Vec::new(),
            is_left: true,
        };
        self.nodes.insert(node_hash.clone(), node.clone());
        node
    }

    fn new() -> MerkleTree {
        MerkleTree {
            root_hash: Vec::new(),
            nodes: BTreeMap::new(),
        }
    }
}

#[test]
fn test() {
    let mut data = Vec::new();
    data.push(b"vec1".to_vec());
    data.push(b"vec2".to_vec());
    data.push(b"vec3".to_vec());
    data.push(b"vec4".to_vec());
    data.push(b"vec5".to_vec());
    data.push(b"vec6".to_vec());

    let merkle = MerkleTree::build(&data);
    let data_hash = twox_64(&*b"vec3".to_vec()).to_vec();
    let path = merkle.merkle_path(&data_hash);
    for x in &path {
        // println!("merkle_path: {:?}: {}", x.0, &x.1);
    }
    let result = MerkleTree::verify_data(&data_hash, &path,
                                         &merkle.root_hash);
    // println!("result: {}", result);
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
        // println!("{}", year);
        let mut birthed = "0";
        if year >= birth {
            birthed = "1";
        }
        let to_add_data = year.to_string() + ":" + birthed;
        data.push(to_add_data.as_bytes().to_vec());
    }
    let v = MerkleTree::build(&data);
    let path = v.merkle_path(&to_validate_data_hash);
    for x in &path {
        // println!("merkle_path: {:?}: {}", x.0, &x.1);
    }
    let result = MerkleTree::verify_data(&to_validate_data_hash, &path,
                                         &v.root_hash);
    // println!("result: {}", result);
}

#[test]
fn test_vec_str() {
    let mut q = "0123456789:".as_bytes().into_iter()
        // .chain(b"1996".into_iter())
        .copied().collect::<Vec<u8>>();
    // println!("{:?}, {}", q, sp_std::str::from_utf8(&q).unwrap());
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
    // println!("data: {}", sp_std::str::from_utf8(&data).unwrap());
}
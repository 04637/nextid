#![cfg_attr(not(feature = "std"), no_std)]

use sp_std::borrow::Borrow;
use sp_std::cell::{Ref, RefCell};
use sp_std::fmt::{Display, Formatter};
use sp_std::hash::{Hash};
use sp_std::rc::Rc;
use sp_std::str::*;
use sp_std::vec::Vec;
use sp_io::hashing::twox_64;

pub struct MerkleTree {
    tree_root: TreeNodeType,
    tree_leaf: Vec<TreeNodeType>,
}

type TreeNodeType = Rc<RefCell<TreeNode>>;

pub struct TreeNode {
    // 真实值
    pub value: Vec<u8>,
    // 哈希值
    pub hash: Vec<u8>,
    // 交易序号
    pub trade_no: usize,
    // 验证路径
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
            left_hash = TreeNode::unwrap(left).hash.clone();
        };
        if let Some(right) = self.right.as_ref() {
            right_hash = TreeNode::unwrap(right).hash.clone()
        };
        if let Some(parent) = self.parent.as_ref() {
            parent_hash = TreeNode::unwrap(parent).hash.clone();
        }
        write!(f, "trade_no: {}, value: {}, isLeft: {}
        hash: {:?},
        left: {:?},
        right: {:?},
        parent: {:?}\n",
               self.trade_no,
               sp_std::str::from_utf8(&*self.value).unwrap(),
               self.is_left,
               self.hash,
               left_hash,
               right_hash,
               parent_hash
        )
    }
}

impl TreeNode {
    // 原始数据 => 默克尔树
    pub fn build(data: &Vec<Vec<u8>>) -> MerkleTree {
        let mut data_vec = Vec::new();
        let mut tree_leaf = Vec::new();
        for (i, val) in data.iter().enumerate() {
            let tree_data =
                Rc::new(RefCell::new(Self::new_data_node(val.clone(),
                                                         twox_64(val.as_ref()).to_vec(),
                                                         i + 1)),
                );
            data_vec.push(Rc::clone(&tree_data));
            tree_leaf.push(Rc::clone(&tree_data))
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
                    log::info!("{}", Self::unwrap(&last_tree));
                    log::info!("{}", Self::unwrap(&x));
                    tree_vec.push(parent);
                }
                None => {
                    last = Some(Rc::clone(&x));
                }
            }
        }
        // 结束时last没上树
        if let Some(last_tree) = last {
            log::info!("{}", Self::unwrap(&last_tree));
            tree_vec.push(Rc::from(last_tree));
        }
        log::info!("================================================================");
        Self::build_from_vec_recur(tree_vec)
    }

    // 两节点组合为一个
    fn combine_node(left: TreeNodeType, right: TreeNodeType) -> TreeNodeType {
        let parent;
        let left_index;
        let right_index;
        {
            let left_ref = Self::unwrap(&left);
            let right_ref = Self::unwrap(&right);
            let mut to_hash = Vec::new();
            to_hash.append(&mut left_ref.hash.clone());
            to_hash.append(&mut right_ref.hash.clone());
            let hashed = twox_64(&*to_hash);
            let hash_vec: Vec<u8> = hashed.to_vec();
            left_index = left_ref.trade_no.clone();
            right_index = right_ref.trade_no.clone();
            let index = left_ref.trade_no + right_ref.trade_no;
            parent = Rc::new(RefCell::new(Self::new_tree_node(hash_vec, index,
                                                              Some(Rc::clone(&left)),
                                                              Some(Rc::clone(&right)))));
        }
        if left_index % 2 == 0 {
            (*left).borrow_mut().trade_no = left_index - 1;
        }
        (*left).borrow_mut().parent = Some(Rc::clone(&parent));
        (*left).borrow_mut().is_left = true;

        if right_index % 2 != 0 {
            (*right).borrow_mut().trade_no = right_index + 1;
        }
        (*right).borrow_mut().parent = Some(Rc::clone(&parent));
        (*right).borrow_mut().is_left = false;
        parent
    }

    fn new_data_node(value: Vec<u8>, hash: Vec<u8>, index: usize) -> TreeNode {
        TreeNode {
            value,
            hash,
            trade_no: index,
            left: None,
            right: None,
            parent: None,
            is_left: true,
        }
    }

    fn new_tree_node(hash: Vec<u8>, index: usize,
                     left: Option<TreeNodeType>,
                     right: Option<TreeNodeType>) -> TreeNode {
        TreeNode {
            value: Vec::new(),
            hash,
            trade_no: index,
            left,
            right,
            parent: None,
            is_left: true,
        }
    }

    // 解包
    fn unwrap(wrapped: &TreeNodeType) -> Ref<TreeNode> {
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
    /// * `trade_index` - 交易索引, 1开始
    pub fn merkle_path(&self, trade_no: usize) -> Vec<(usize, Vec<u8>)> {
        let data_node = &self.tree_leaf[trade_no - 1];
        let mut path: Vec<(usize, Vec<u8>)> = Vec::new();
        Self::recur_upward(data_node, &mut path);
        path
    }

    /// # 根据默克尔路径验证数据
    /// * `data` - 待验证原始数据
    /// * `path` - 默克尔路径 `vec![hash1, hash2]`
    /// * `root_hash` - 根hash
    pub fn verify_data(data: &Vec<u8>, path: &Vec<(usize, Vec<u8>)>, root_hash: &Vec<u8>) -> bool {
        let mut data_hash = twox_64(data).to_vec();
        for (trade_no, path_hash) in path {
            if trade_no % 2 == 0 {
                data_hash.append(&mut path_hash.clone());
                data_hash = Vec::from(twox_64(&*data_hash));
            } else {
                let mut path_hash = path_hash.clone();
                path_hash.append(&mut data_hash.clone());
                data_hash = Vec::from(twox_64(&*path_hash));
            }
            log::info!("verify_data: {:?}", data_hash);
        }
        &data_hash == root_hash
    }

    /// 向上递归, 找兄弟节点
    fn recur_upward(tree_node: &TreeNodeType, path: &mut Vec<(usize, Vec<u8>)>) {
        let unwrap_cur = TreeNode::unwrap(tree_node);
        let parent = &unwrap_cur.parent;
        if let Some(parent) = parent {
            // 有父节点, 留下兄弟节点, 继续向上
            if unwrap_cur.is_left {
                if let Some(right_node) = &TreeNode::unwrap(parent).right {
                    let unwrap_right = TreeNode::unwrap(right_node);
                    path.push((unwrap_right.trade_no, unwrap_right.hash.clone()));
                }
            } else {
                if let Some(left_node) = &TreeNode::unwrap(parent).left {
                    let unwrap_left = TreeNode::unwrap(left_node);
                    path.push((unwrap_left.trade_no, unwrap_left.hash.clone()));
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
    data.push(b"vec1".to_vec());
    data.push(b"vec2".to_vec());
    data.push(b"vec3".to_vec());
    data.push(b"vec4".to_vec());
    data.push(b"vec5".to_vec());
    data.push(b"vec6".to_vec());
    let v = TreeNode::build(&data);
    // log::info!("{}", (*v.tree_root).borrow());
    // log::info!("{}", (*v.tree_leaf).borrow().len());
    let path = v.merkle_path(2);
    for x in &path {
        log::info!("merkle_path: {}: {:?}", x.0, &x.1);
    }
    // let path: Vec<Vec<u8>> = path.into_iter().map(
    //     |v| v.1
    // ).collect::<Vec<Vec<u8>>>();
    let result = MerkleTree::verify_data(&b"vec2".to_vec(), &path,
                                         &TreeNode::unwrap(&v.tree_root).hash);
    log::info!("result: {}", result);
}
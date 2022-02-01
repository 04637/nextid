use std::cell::{Ref, RefCell};
use std::collections::hash_map::DefaultHasher;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::str::*;

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
    // 索引序列
    pub index: Box<u32>,
    // 验证路径
    pub left: Option<TreeNodeType>,
    pub right: Option<TreeNodeType>,
    pub parent: Option<TreeNodeType>,
    pub is_left: bool,
}

impl Display for TreeNode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut left_hash = vec![];
        let mut right_hash = vec![];
        let mut parent_hash = vec![];

        if let Some(left) = &self.left {
            left_hash = TreeNode::unwrap(left).hash.clone();
        };
        if let Some(right) = self.right.as_ref() {
            right_hash = TreeNode::unwrap(right).hash.clone()
        };
        if let Some(parent) = self.parent.as_ref() {
            parent_hash = TreeNode::unwrap(parent).hash.clone();
        }
        write!(f, "index: {}, value: {}, isLeft: {}
        hash: {},
        left: {},
        right: {},
        parent: {}\n",
               self.index,
               from_utf8(&*self.value).unwrap(),
               self.is_left,
               from_utf8(&*self.hash).unwrap(),
               from_utf8(&*left_hash).unwrap(),
               from_utf8(&*right_hash).unwrap(),
               from_utf8(&*parent_hash).unwrap(),
        )
    }
}

impl TreeNode {
    // 原始数据 => 默克尔树
    pub fn build(data: &Vec<String>) -> MerkleTree {
        let mut data_vec = vec![];
        for (i, val) in data.iter().enumerate() {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            let tree_data = Self::new_data_node(String::from(val).into_bytes(),
                                                hasher.finish().to_string().into_bytes(),
                                                Box::new((i + 1) as u32),
            );
            data_vec.push(Rc::new(RefCell::new(tree_data)));
        }
        let root = Self::build_from_vec_recur(data_vec).pop().unwrap();
        MerkleTree {
            tree_root: root,
            // todo
            tree_leaf: vec![],
        }
    }

    // 多节点自下而上递归构建默克尔树
    fn build_from_vec_recur(vec: Vec<TreeNodeType>) -> Vec<TreeNodeType> {
        let mut last = None;
        let mut tree_vec = vec![];
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
                    println!("{}", Self::unwrap(&last_tree));
                    println!("{}", Self::unwrap(&x));
                    tree_vec.push(parent);
                }
                None => {
                    last = Some(Rc::clone(&x));
                }
            }
        }
        // 结束时last没上树
        if let Some(last_tree) = last {
            println!("{}", Self::unwrap(&last_tree));
            tree_vec.push(Rc::from(last_tree));
        }
        println!("================================================================");
        Self::build_from_vec_recur(tree_vec)
    }

    // 两节点组合为一个
    fn combine_node(left: TreeNodeType, right: TreeNodeType) -> TreeNodeType {
        let parent;
        {
            let left_ref = Self::unwrap(&left);
            let right_ref = Self::unwrap(&right);
            let left_val = from_utf8(&*left_ref.hash).unwrap();
            let right_val = from_utf8(&*right_ref.hash).unwrap();
            let mut hasher = DefaultHasher::new();
            (left_val.to_owned() + right_val).hash(&mut hasher);
            let hash_vec: Vec<u8> = hasher.finish().to_string().into_bytes();
            let index = (left_ref.index.to_string().to_owned() + &*right_ref.index.to_string())
                .parse::<u32>().unwrap();
            parent = Rc::new(RefCell::new(Self::new_tree_node(hash_vec, Box::new(index),
                                                              Some(Rc::clone(&left)),
                                                              Some(Rc::clone(&right)))));
        }
        (*left).borrow_mut().parent = Some(Rc::clone(&parent));
        (*left).borrow_mut().is_left = true;
        (*right).borrow_mut().parent = Some(Rc::clone(&parent));
        (*right).borrow_mut().is_left = false;
        parent
    }

    fn new_data_node(value: Vec<u8>, hash: Vec<u8>, index: Box<u32>) -> TreeNode {
        TreeNode {
            value,
            hash,
            index,
            left: None,
            right: None,
            parent: None,
            is_left: true,
        }
    }

    fn new_tree_node(hash: Vec<u8>, index: Box<u32>,
                     left: Option<TreeNodeType>,
                     right: Option<TreeNodeType>) -> TreeNode {
        TreeNode {
            value: vec![],
            hash,
            index,
            left,
            right,
            parent: None,
            is_left: true,
        }
    }

    fn unwrap(wrapped: &TreeNodeType) -> Ref<TreeNode> {
        Ref::map(
            (**wrapped).borrow(),
            |borrowed| { &(*borrowed) },
        )
    }
}

impl MerkleTree {
    // log2(n) 个节点hash
    fn merkle_path(&self) {}
}

#[test]
fn test() {
    let mut data = Vec::new();
    for i in 10..15 {
        data.push((i + i + 1).to_string());
    }
    let v = TreeNode::build(&data);
    println!("{}", (*v.tree_root).borrow());
}
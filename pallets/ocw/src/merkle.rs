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
    // 交易序号
    pub trade_no: Box<usize>,
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
        write!(f, "trade_no: {}, value: {}, isLeft: {}
        hash: {},
        left: {},
        right: {},
        parent: {}\n",
               self.trade_no,
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
        let mut tree_leaf = vec![];
        for (i, val) in data.iter().enumerate() {
            let mut hasher = DefaultHasher::new();
            val.hash(&mut hasher);
            let tree_data =
                Rc::new(RefCell::new(Self::new_data_node(String::from(val).into_bytes(),
                                                         hasher.finish().to_string().into_bytes(),
                                                         Box::new(i + 1))),
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
            let index = (left_ref.trade_no.to_string().to_owned() + &*right_ref.trade_no.to_string())
                .parse::<usize>().unwrap();
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

    fn new_data_node(value: Vec<u8>, hash: Vec<u8>, index: Box<usize>) -> TreeNode {
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

    fn new_tree_node(hash: Vec<u8>, index: Box<usize>,
                     left: Option<TreeNodeType>,
                     right: Option<TreeNodeType>) -> TreeNode {
        TreeNode {
            value: vec![],
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
        let mut path: Vec<(usize, Vec<u8>)> = vec![];
        Self::recur_upward(data_node, &mut path);
        path
    }

    /// # 根据默克尔路径验证数据
    /// * `data` - 待验证原始数据
    /// * `path` - 默克尔路径 `vec![hash1, hash2]`
    /// * `root_hash` - 根hash
    pub fn verify_data(data: &str, path: &Vec<Vec<u8>>, root_hash: &Vec<u8>) -> bool {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let mut data_hash = hasher.finish().to_string();
        for path_hash in path {
            let to_hash = data_hash.to_owned() + from_utf8(&*path_hash).unwrap();
            let mut hasher = DefaultHasher::new();
            to_hash.hash(&mut hasher);
            data_hash = hasher.finish().to_string();
            println!("verify_data: {}", data_hash);
        }
        &data_hash.into_bytes() == root_hash
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
                    path.push((*unwrap_right.trade_no, unwrap_right.hash.clone()));
                }
            } else {
                if let Some(left_node) = &TreeNode::unwrap(parent).left {
                    let unwrap_left = TreeNode::unwrap(left_node);
                    path.push((*unwrap_left.trade_no, unwrap_left.hash.clone()));
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
    for i in 10..16 {
        data.push((i + i + 1).to_string());
    }
    let v = TreeNode::build(&data);
    // println!("{}", (*v.tree_root).borrow());
    // println!("{}", (*v.tree_leaf).borrow().len());
    let path = v.merkle_path(1);
    for x in &path {
        println!("merkle_path: {}: {}", x.0, from_utf8(&x.1).unwrap());
    }
    let path: Vec<Vec<u8>> = path.into_iter().map(
        |v| v.1
    ).collect::<Vec<Vec<u8>>>();
    let result = MerkleTree::verify_data("21", &path,
                                         &TreeNode::unwrap(&v.tree_root).hash);
    println!("result: {}", result);
}
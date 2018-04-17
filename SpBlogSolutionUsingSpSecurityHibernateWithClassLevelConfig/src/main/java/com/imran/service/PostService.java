package com.imran.service;

import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.imran.common.BaseService;
import com.imran.dao.PostDao;
import com.imran.model.Post;

@Service
@Transactional
public class PostService extends BaseService{

	
	@Autowired
	PostDao postDao;

	
    public void createOrUpdatePost(Post post){
    	postDao.addProduct(post);
    }
	
	public void updateProduct(Post post){
		postDao.updateProduct(post);
	}
	
	public List<Post> postList(){
		return postDao.listProduct();
	}
	
	public Post findByPostId(long postId){
		return postDao.getProductById(postId);
	}
	
	public void removeProduct(long postId){
		postDao.removeProduct(postId);
	}

}

package com.imran.dao;

import java.util.List;

import javax.transaction.Transactional;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import com.imran.common.BaseService;
import com.imran.model.Post;


@Repository
public class PostDao extends BaseService{
	
	@Autowired
	private SessionFactory sessionFactory;
	
//	private Session getCurrentSession() {
//		return sessionFactory.getCurrentSession();
//	}
	
	
	@Transactional
    public void addProduct(Post post){
		sessionFactory.getCurrentSession().save(post);
    }
	
	@Transactional
	public void updateProduct(Post post){
		sessionFactory.getCurrentSession().update(post);
	}
	
	@Transactional
	@SuppressWarnings("unchecked")
	public List<Post> listProduct() {
		return (List<Post>) sessionFactory.getCurrentSession().createCriteria(Post.class).list();
	}
	
	@Transactional
	@SuppressWarnings("unchecked")
	public Post getProductById(long postId){
		return (Post) sessionFactory.getCurrentSession().get(Post.class, postId);
	}

	@Transactional
	public void removeProduct(long productId){
		Post post = (Post)sessionFactory.getCurrentSession().load(Post.class, productId);
		if(post != null){
			if(!post.getFeature_image().equals(""))
				System.out.println("Delete fImg NFame:"+post.getFeature_image());
			removeFile(post.getFeature_image());
			sessionFactory.getCurrentSession().delete(post);
		}
	}
	

}

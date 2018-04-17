package com.imran.dao;


import java.util.List;


import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.imran.model.Post;

@Repository
public class TestDao {
	
	@Autowired
	private SessionFactory sessionFactory;
	
	private Session getCurrentSession() {
		return sessionFactory.getCurrentSession();
	}
	

	@SuppressWarnings("unchecked")
	public List<Post> listProduct() {
		return (List<Post>) getCurrentSession().createCriteria(Post.class).list();
	}

}

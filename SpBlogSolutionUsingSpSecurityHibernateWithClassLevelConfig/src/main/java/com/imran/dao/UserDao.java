package com.imran.dao;

import java.util.List;
import javax.transaction.Transactional;
import org.hibernate.Query;
import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import com.imran.model.User;

@Repository
public class UserDao {
	
	
	

	@Autowired
	private SessionFactory sessionFactory;
	
//	private Session getCurrentSession() {
//		return sessionFactory.getCurrentSession();
//	}
	
	@Transactional
    public void add(User user){
    	sessionFactory.getCurrentSession().save(user);
    }
	
	@Transactional
	public void update(User user){
		sessionFactory.getCurrentSession().update(user);
	}
	
	@Transactional
	@SuppressWarnings("unchecked")
	public List<User> list() {
		return (List<User>) sessionFactory.getCurrentSession().createCriteria(User.class).list();
	}
	@Transactional
	@SuppressWarnings("unchecked")
	public User getById(long userId){
		return (User) sessionFactory.getCurrentSession().get(User.class, userId);
	}
	
	@Transactional
	@SuppressWarnings("unchecked")
	public User getUserByEmail(String email) {
		  Query query = sessionFactory.getCurrentSession().createQuery("from User where email = :email");
		  query.setParameter("email", email);
		  if(query != null){
			  return (User) query.list().get(0);
		  }
	      return null;
		}
	
//	public User getByEmail(String email) {
//		return sessionFactory.getCurrentSession().createQuery("DELETE FROM user WHERE id = "+email);
//	}

	@Transactional
	public void remove(long userId){
		User user = (User)sessionFactory.getCurrentSession().load(User.class, userId);
		if(user != null){
			sessionFactory.getCurrentSession().delete(user);
		}
	}
	

}

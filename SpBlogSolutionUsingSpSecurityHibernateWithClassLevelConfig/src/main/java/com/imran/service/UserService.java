package com.imran.service;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.SessionFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.imran.dao.UserDao;
import com.imran.model.User;


@Service
@Transactional
public class UserService {
	


	@Autowired
	UserDao userDao;
	
	
	public void userRegistration(User user) {
		userDao.add(user);
	}
	

	public User userLogin(String email, String password){
		User logUser = null;
		List<User> userList = new ArrayList<User>();
		String getUserQuery ="select * from user WHERE email='"+email+"'";
		User singleUser = userDao.getUserByEmail(email);
		if(singleUser !=null){
		   if(singleUser.getPassword().equals(password)){
			   logUser = singleUser;  
		   }
		}
		return logUser;	
	}
	
	
    public void add(User user){
    	userDao.add(user);
    }
	
	public void update(User user){
		userDao.update(user);
	}
	
	public List<User> list(){
		return userDao.list();
	}
	
	public User getById(long id){
		return userDao.getById(id);
	}
	
	public void removeById(long id){
		userDao.remove(id);
	}


}
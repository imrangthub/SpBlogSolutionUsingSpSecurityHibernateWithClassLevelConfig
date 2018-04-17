package com.imran.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.imran.dao.TestDao;

import com.imran.model.Post;



@Service
@Transactional
public class TestService{

	@Autowired
	private TestDao testDao;
	
	public List<Post> postList(){
	return testDao.listProduct();
}


}

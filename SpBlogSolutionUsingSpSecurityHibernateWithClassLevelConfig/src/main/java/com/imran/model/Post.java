package com.imran.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import org.hibernate.annotations.Type;

@Entity
@Table(name="post")
public class Post{
	
	public Post(){}

	public Post(String title, String body, String feature_image) {
		this.title = title;
		this.body = body;
		this.feature_image = feature_image;
	}

	public Post(long id, String title, String body, String feature_image, int active_status) {
		super();
		this.id = id;
		this.title = title;
		this.body = body;
		this.feature_image = feature_image;
		this.active_status = active_status;
	}

	@Id
	@GeneratedValue(strategy=GenerationType.AUTO)
	private long id;
	
	@Column(nullable = false)
	String title;
	
	@Column(nullable = false)
	@Type(type="text")
	String body;
	
	@Column(nullable = true)
	String feature_image;

	@Column(nullable = true)
    int active_status = 1;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public String getBody() {
		return body;
	}

	public void setBody(String body) {
		this.body = body;
	}

	public String getFeature_image() {
		return feature_image;
	}

	public void setFeature_image(String feature_image) {
		this.feature_image = feature_image;
	}

	public int getActive_status() {
		return active_status;
	}

	public void setActive_status(int active_status) {
		this.active_status = active_status;
	}
    

   
    
    

}

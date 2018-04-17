<%@ page isELIgnored="false"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<jsp:include page="/WEB-INF/views/_partial/_header.jsp" />

    <!-- Main jumbotron for a primary marketing message or call to action -->
    <div class="jumbotron">
      <div class="container">
        <h1>Current Post List</h1>
        <p>This is a Project where I user Spring 5.2 for mvc and Jdbc</p>
        <p><a class="btn btn-primary btn-lg pull-right" href="/SpBlogSolutionUsingSpSecurityHibernateWithClassLevelConfig/post/create" role="button">Add new Post</a></p>
      </div>
    </div>

    <div class="container">
      <!-- Example row of columns -->
      <div class="row">
	    <c:forEach items="${postList }" var="post">
	       <div class="col-md-12 well">
	           <div id="imgDiv">
	           	<c:choose>
									 <c:when test="${empty post.feature_image }"><h4>NO IMAGE</h4></c:when>
									 <c:otherwise>
														
	             <img src="<c:url value="/resources/imgFolder/${post.feature_image}"/>" width="200px" height="150px"/>
									 </c:otherwise>
							</c:choose>

	           </div>
	          <h2>${post.title }</h2>
	          <p>
	          ${post.body }
              </p>
	          <a class="btn btn-default btn-warning" href="/SpBlogSolutionUsingSpSecurityHibernateWithClassLevelConfig/post/edit/${post.id }" role="button">Edit</a>
	          <a class="btn btn-default  btn-danger" href="/SpBlogSolutionUsingSpSecurityHibernateWithClassLevelConfig/post/delete/${post.id }" role="button">Delete</a>
	        </div>
	        
	        
	    </c:forEach>   
      </div>
	<jsp:include page="/WEB-INF/views/_partial/_footerMenu.jsp" />
</div>
<!-- /container -->
<jsp:include page="/WEB-INF/views/_partial/_footer.jsp" />
<%@ page isELIgnored="false"%>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<jsp:include page="/WEB-INF/views/_partial/_header.jsp" />

    <!-- Main jumbotron for a primary marketing message or call to action -->
    <div class="jumbotron">
      <div class="container">
        <h2>Welcome to MD IMRAN HOSSAIN</h2>
        <p>This is a Project where I user Spring 5.2 for mvc and Jdbc</p>
        <p><a class="btn btn-primary btn-lg" href="/SpBlogSolutionUsingSpSecurityHibernateWithClassLevelConfig/post/" role="button">Manage Post</a></p>
      </div>
    </div>

    <div class="container">
      <!-- Example row of columns -->
      <div class="row">
              <c:if test="${not empty message}">
		    <div  class="alert alert-${css} alert-dismissible well" role="alert">
			<button type="button" class="close" data-dismiss="alert" aria-label="Close">
				<span aria-hidden="true">×</span>
			</button>
			<strong>${message}</strong>
		    </div>
		</c:if>
        <div class="col-md-4">
          <h2>User Info: </h2>
          <p>Name: MD IMRAN HOSSAIN </p>
          <p>Email: imranmadbar@gmail.com </p>
          <p><a class="btn btn-default" href="#" role="button">Edit Profile</a></p>
        </div>
      </div>
      
	<jsp:include page="/WEB-INF/views/_partial/_footerMenu.jsp" />
</div>
<!-- /container -->
<jsp:include page="/WEB-INF/views/_partial/_footer.jsp" />
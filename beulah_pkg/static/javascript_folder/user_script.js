function alertSuccess(titleContent, textContent){
    Swal.fire({
        icon: 'success',
        title: titleContent,
        text: textContent,
        confirmButtonText: 'Okay',      
        showConfirmButton: true,
        customClass: {
            title: 'my-swal-title',
            confirmButton: 'my-swal-confirm-btn',
        }
    });
}

function alertError(titleContent, textContent){
    Swal.fire({
        icon: 'error',
        title: titleContent,
        text: textContent,
        confirmButtonText: 'Okay',      
        showConfirmButton: true,
        customClass: {
            title: 'my-swal-title',
            confirmButton: 'my-swal-confirm-btn',
        }
    });
}

document.addEventListener("DOMContentLoaded", function() {
    let preloader = document.getElementById("preloader");
    preloader.style.transition = "opacity 0.5s ease-out";
    preloader.style.opacity = "0";
    
    setTimeout(() => {
        preloader.style.display = "none";
        let mainContent = document.getElementById('content-container')
        mainContent.classList.add("loaded");
    }, 500);


    AOS.init({
        duration:1000, 
        once: true,
        easing: 'ease-in-out'
    });



    let lastScrollTop = 0;
    const nav = document.querySelector(".all-nav");

    window.addEventListener("scroll", function () {
        let scrollTop = window.scrollY;

        requestAnimationFrame(() => {
            if (scrollTop > 60 && lastScrollTop <= 60) {
                nav.classList.add("sticky-nav");
            } else if (scrollTop <= 60 && lastScrollTop > 60) {
                nav.classList.remove("sticky-nav");
            }
            lastScrollTop = scrollTop;
        });
    });


    const toggler = document.querySelector('.hamburger');
    const navMenu = document.querySelector('.nav-menu');
    const body = document.body;
  
    toggler.addEventListener('click', () => {
      navMenu.classList.toggle('active');
      toggler.classList.toggle('open')
      body.classList.toggle('nav-open');
    });


    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const subscriberForm = document.getElementById('subscriberForm')
    
    subscriberForm.addEventListener('submit', function(event){
        event.preventDefault()

        const subscriberEmail = document.querySelector('#subscriberForm input[name="subscriber-email"]').value.trim()

        // Check if the email field is empty
        if (!subscriberEmail || subscriberEmail == '') {
            alertError('Oops...', 'Subscriber field cannot be empty. Please Provide a valid email')
            return; // Prevent further execution
        }
        // Make the POST request with fetch
        fetch(this.action, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json', 
                'X-CSRFToken': csrfToken 
            },
            body: JSON.stringify({ subscriberEmail: subscriberEmail })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alertSuccess('Form Submitted', data.message);
                subscriberForm.reset(); 
            } else {
                alertError('Oops...',data.message); 
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alertError('Oops...', 'An error occurred while processing your subscription. Please try again later.');
        });
    })


    // user_javascript.js
    document.getElementById('search-toggle').addEventListener('click', function () {
        var searchInput = document.getElementById('search-input');
        var isHidden = searchInput.style.display === 'none' || searchInput.style.display === '';
    
        if (isHidden) {
        searchInput.style.display = 'block';
        searchInput.style.opacity = '0';   
        setTimeout(() => {
            searchInput.style.opacity = '1'; 
            setTimeout(() => { searchInput.style.display = 'flex';}, 500); 
        }, 0); 
        } else {
        searchInput.style.opacity = '0';    // Start fade-out
        setTimeout(() => { searchInput.style.display = 'none'; }, 500);
        }
    });

    document.getElementById('close-search').addEventListener('click', function () {
        const searchInput = document.getElementById('search-input');
        searchInput.style.opacity = '0';
        setTimeout(function () {
            searchInput.style.display = 'none';
            var form = document.querySelector('#search-input #user-search-input');
            if (form) form.reset();
        }, 500);
    });

    document.getElementById('user-search-input').addEventListener('submit', function (event) {
        var input = document.getElementById('query').value.trim();
        if (!input) {
            event.preventDefault();
            Swal.fire({
                icon: "error",
                title: 'Oops...',
                text: 'Search field cannot be empty',
                showConfirmButton: false,
                timer: 1500
            });
        }
    });

    document.getElementById('year').textContent = new Date().getFullYear();

});


// Timeout Fallback: Auto-hide loader after max 1 min
setTimeout(() => {
    let preloader = document.getElementById("preloader");
    let mainContent = document.getElementById("content-container");

    preloader.style.opacity = "0";
    setTimeout(() => {
        preloader.style.display = "none";
        mainContent.style.display = "block";
    }, 500);
}, 10000); // Max wait time


$(document).ready(function () {
    // Show the "Features" dropdown when the mouse enters the "Features" menu item
    $('#features-button').mouseenter(function () {
        $('#drop-down-features').show();
    });

    // Hide the "Features" dropdown when the mouse leaves the "Features" menu item
    $('#features-button').mouseleave(function () {
        $('#drop-down-features').hide();
    });

    // Show the user profile dropdown when the mouse enters the user profile menu item
    $('#profile-button').mouseenter(function () {
        $('#drop-down-profile').show();
    });

    // Hide the user profile dropdown when the mouse leaves the user profile menu item
    $('#profile-button').mouseleave(function () {
        $('#drop-down-profile').hide();
    });
});

  // homepage-button
  document.querySelector("#homepage-button").addEventListener("click", function () {
    window.location.href = "/register";
})

// Custom JavaScript for Capiscio Python SDK documentation

document.addEventListener('DOMContentLoaded', function() {
  // Add copy success feedback
  document.querySelectorAll('.md-clipboard').forEach(function(button) {
    button.addEventListener('click', function() {
      button.classList.add('md-clipboard--copied');
      setTimeout(function() {
        button.classList.remove('md-clipboard--copied');
      }, 2000);
    });
  });

  // Track external links
  document.querySelectorAll('a[href^="http"]').forEach(function(link) {
    if (!link.href.includes(window.location.hostname)) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer');
    }
  });

  // Smooth scroll to anchors
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // Add "Back to top" functionality
  const backToTop = document.querySelector('.md-top');
  if (backToTop) {
    backToTop.addEventListener('click', function(e) {
      e.preventDefault();
      window.scrollTo({
        top: 0,
        behavior: 'smooth'
      });
    });
  }
});

// Analytics for documentation usage (if Google Analytics is configured)
if (typeof ga !== 'undefined') {
  // Track code copy events
  document.querySelectorAll('.md-clipboard').forEach(function(button) {
    button.addEventListener('click', function() {
      const code = button.parentElement.querySelector('code');
      if (code && ga) {
        ga('send', 'event', 'Code', 'Copy', code.textContent.substring(0, 100));
      }
    });
  });

  // Track external link clicks
  document.querySelectorAll('a[href^="http"]').forEach(function(link) {
    link.addEventListener('click', function() {
      if (ga) {
        ga('send', 'event', 'External Link', 'Click', link.href);
      }
    });
  });
}

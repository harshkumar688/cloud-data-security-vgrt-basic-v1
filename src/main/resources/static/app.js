/**
 * V-GRT SECURE CLOUD — Interactive UI Scripts
 * Handles: Theme switching, mobile navigation, dropdowns, modals, and file dropzone
 */
(function () {
  'use strict';

  // 1. THEME SWITCHING ENGINE
  const THEME_KEY = 'vgrt_theme_preference';

  function initTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (prefersDark ? 'dark' : 'dark'); // Default to sleek dark monochrome
    applyTheme(initialTheme);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
    updateThemeIcons(theme);
  }

  function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(newTheme);
  }

  function updateThemeIcons(theme) {
    const toggles = document.querySelectorAll('.theme-toggle-btn');
    toggles.forEach(btn => {
      btn.innerHTML = theme === 'dark'
        ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
        : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
      btn.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
      btn.setAttribute('title', `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`);
    });
  }

  // 2. MOBILE SIDEBAR DRAWER
  function initMobileNav() {
    const trigger = document.querySelector('.mobile-menu-trigger');
    const sidebar = document.querySelector('.app-sidebar');
    let backdrop = document.querySelector('.mobile-sidebar-backdrop');

    if (!backdrop && sidebar) {
      backdrop = document.createElement('div');
      backdrop.className = 'mobile-sidebar-backdrop';
      document.body.appendChild(backdrop);
    }

    function openMobileSidebar() {
      if (sidebar) sidebar.classList.add('mobile-open');
      if (backdrop) backdrop.classList.add('active');
      document.body.style.overflow = 'hidden';
    }

    function closeMobileSidebar() {
      if (sidebar) sidebar.classList.remove('mobile-open');
      if (backdrop) backdrop.classList.remove('active');
      document.body.style.overflow = '';
    }

    if (trigger) {
      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        if (sidebar && sidebar.classList.contains('mobile-open')) {
          closeMobileSidebar();
        } else {
          openMobileSidebar();
        }
      });
    }

    if (backdrop) {
      backdrop.addEventListener('click', closeMobileSidebar);
    }

    // Close on navigation link click on mobile
    if (sidebar) {
      sidebar.querySelectorAll('.nav-item a').forEach(link => {
        link.addEventListener('click', () => {
          if (window.innerWidth < 1024) closeMobileSidebar();
        });
      });
    }
  }

  // 3. ACCESSIBLE DROPDOWNS
  function initDropdowns() {
    document.addEventListener('click', (e) => {
      const trigger = e.target.closest('.dropdown-trigger');
      const activeDropdown = trigger ? trigger.closest('.dropdown') : null;

      // Close all other dropdowns
      document.querySelectorAll('.dropdown.open').forEach(dd => {
        if (dd !== activeDropdown) dd.classList.remove('open');
      });

      if (activeDropdown) {
        e.preventDefault();
        e.stopPropagation();
        activeDropdown.classList.toggle('open');
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        document.querySelectorAll('.dropdown.open').forEach(dd => dd.classList.remove('open'));
      }
    });
  }

  // 4. ACCESSIBLE MODALS
  window.VGRT = window.VGRT || {};
  window.VGRT.openModal = function (modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    const focusable = modal.querySelector('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
    if (focusable) focusable.focus();
  };

  window.VGRT.closeModal = function (modalId) {
    const modal = document.getElementById(modalId);
    if (!modal) return;
    modal.classList.remove('active');
    document.body.style.overflow = '';
  };

  function initModals() {
    document.addEventListener('click', (e) => {
      // Open modal trigger
      const openTrigger = e.target.closest('[data-modal-target]');
      if (openTrigger) {
        e.preventDefault();
        const targetId = openTrigger.getAttribute('data-modal-target');
        window.VGRT.openModal(targetId);
        return;
      }

      // Close modal trigger
      const closeTrigger = e.target.closest('[data-modal-close]');
      if (closeTrigger) {
        e.preventDefault();
        const modal = closeTrigger.closest('.modal-overlay');
        if (modal) window.VGRT.closeModal(modal.id);
        return;
      }

      // Backdrop click
      if (e.target.classList.contains('modal-overlay')) {
        window.VGRT.closeModal(e.target.id);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const activeModal = document.querySelector('.modal-overlay.active');
        if (activeModal) {
          window.VGRT.closeModal(activeModal.id);
        }
      }
    });
  }

  // 5. STYLIZED FILE DROPZONE HELPER
  function initFileDropzones() {
    const dropzones = document.querySelectorAll('.file-dropzone');
    dropzones.forEach(zone => {
      const input = zone.querySelector('input[type="file"]');
      const filenameLabel = zone.querySelector('.dropzone-filename');

      if (!input) return;

      input.addEventListener('change', () => {
        if (input.files && input.files.length > 0) {
          const file = input.files[0];
          const sizeKb = (file.size / 1024).toFixed(1);
          if (filenameLabel) {
            filenameLabel.innerHTML = `<strong>${file.name}</strong> (${sizeKb} KB ready to encrypt)`;
            filenameLabel.classList.add('text-primary');
          }
        }
      });

      ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          zone.classList.add('dragover');
        });
      });

      ['dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, (e) => {
          e.preventDefault();
          e.stopPropagation();
          zone.classList.remove('dragover');
        });
      });
    });
  }

  // DOMContentLoaded initialization
  document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initMobileNav();
    initDropdowns();
    initModals();
    initFileDropzones();

    // Bind theme toggle clicks
    document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
      btn.addEventListener('click', toggleTheme);
    });
  });

})();

jQuery(function($){
  function escapeHtml(s){
    return String(s).replace(/[&<>"'`=\/]/g, function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','/':'&#47;','`':'&#96;','=':'&#61;','\\':'&#92;'}[c];
    });
  }

  function renderResults($target, res){
    if(!res){ $target.html('<div class="notice notice-error"><p>Empty response.</p></div>'); return; }
    var html = '';
    if(res.message){
      html += '<p><strong>' + escapeHtml(res.message) + '</strong></p>';
    }
    if(typeof res.filesChecked !== 'undefined'){
      html += '<p>Files checked: <strong>' + escapeHtml(res.filesChecked) + '</strong></p>';
    }
    if(res.errors && res.errors.length){
      html += '<div class="phpguard-errors"><ol>';
      res.errors.forEach(function(e){
        html += '<li><div><code>' + escapeHtml(e.file || '') + '</code></div>'
             +  '<div style="margin-top:4px; white-space:pre-wrap;">' + escapeHtml(e.message || '') + '</div></li>';
      });
      html += '</ol></div>';
    }

    if(res.indicators && res.indicators.length){
      html += '<h4 style="margin-top:18px;">Suspicious indicators</h4>';
      html += '<p style="margin-top:6px;">These are informational only. Nothing is executed.</p>';
      html += '<div class="phpguard-indicators" style="overflow:auto;">';
      var hasFile = false;
      for(var jf=0;jf<res.indicators.length;jf++){
        if(res.indicators[jf] && res.indicators[jf].file){ hasFile = true; break; }
      }
      html += '<table class="widefat striped" style="margin-top:8px;">';
      html += '<thead><tr>'
           +  '<th>Severity</th><th>Indicator</th>'
           +  (hasFile ? '<th>File</th>' : '')
           +  '<th>Line</th><th>What / Next</th><th>Excerpt</th>'
           +  '</tr></thead><tbody>';
      for(var j=0;j<res.indicators.length;j++){
        var ind = res.indicators[j];
        html += '<tr>';
        html += '<td><strong>'+escapeHtml(ind.severity||'')+'</strong></td>';
        html += '<td>'+escapeHtml(ind.indicator||'')+'</td>';
        if(hasFile){ html += '<td><code>'+escapeHtml(ind.file||'')+'</code></td>'; }
        html += '<td>'+escapeHtml(String(ind.line||''))+'</td>';
        var whatNext = '';
        if(ind.what){ whatNext += escapeHtml(ind.what); }
        if(ind.next){ whatNext += (whatNext ? '<br><em>Next:</em> ' : '') + escapeHtml(ind.next); }
        html += '<td>'+ whatNext +'</td>';
        html += '<td><code>'+escapeHtml(ind.excerpt||'')+'</code></td>';
        html += '</tr>';
      }
      html += '</tbody></table></div>';
    }
    $target.html(html || '<p>No details.</p>');
  }

  function activateTab(tabKey){
    if(!tabKey){ tabKey = 'plugin'; }
    $('.phpguard-tabs-nav a.nav-tab').removeClass('nav-tab-active');
    $('.phpguard-tabs-nav a.nav-tab[data-phpguard-tab="' + tabKey + '"]').addClass('nav-tab-active');

    $('.phpguard-tab-panel').hide().removeClass('phpguard-tab-active');
    var panelId = '#phpguard-tab-' + tabKey;
    var $panel = $(panelId);
    if($panel.length){
      $panel.show().addClass('phpguard-tab-active');
    }
  }

  // Tabs
  $(document).on('click', '.phpguard-tabs-nav a.nav-tab', function(e){
    e.preventDefault();
    var tabKey = $(this).data('phpguard-tab');
    activateTab(tabKey);

    var href = $(this).attr('href');
    if(href && href.charAt(0) === '#' && window.history && history.replaceState){
      history.replaceState(null, document.title, href);
    }
  });

  var hash = window.location.hash || '';
  if(hash.indexOf('#phpguard-tab-') === 0){
    activateTab(hash.replace('#phpguard-tab-',''));
  } else {
    activateTab('plugin');
  }

  // AJAX: Installed plugin scan
  $(document).on('click', '#phpguard-run-scan', function(e){
    e.preventDefault();
    var plugin = $('#phpguard-plugin-select').val() || '';
    var $out = $('#phpguard-scan-result');
    if(!plugin){
      $out.html('<div class="notice notice-error"><p>No plugin selected.</p></div>');
      return;
    }
    $out.html('<p><em>Scanning…</em></p>');
    $.post(PHPGuardFree.ajaxUrl, {
      action: 'phpguard_run_scan',
      nonce: PHPGuardFree.nonce,
      plugin: plugin
    }).done(function(resp){
      if(resp && resp.success){
        renderResults($out, resp.data);
      } else {
        var msg = (resp && resp.data && resp.data.message) ? resp.data.message : 'Scan failed.';
        $out.html('<div class="notice notice-error"><p>' + escapeHtml(msg) + '</p></div>');
      }
    }).fail(function(){
      $out.html('<div class="notice notice-error"><p>Request failed.</p></div>');
    });
  });

  // AJAX: Snippet scan
  $(document).on('click', '#phpguard-run-snippet-scan', function(e){
    e.preventDefault();
    var snippet = $('#phpguard-snippet').val() || '';
    var $out = $('#phpguard-snippet-result');
    if(!snippet.trim()){
      $out.html('<div class="notice notice-error"><p>No code provided.</p></div>');
      return;
    }
    $out.html('<p><em>Scanning…</em></p>');
$.post(PHPGuardFree.ajaxUrl, {
  action: 'phpguard_run_snippet_scan',
  nonce: PHPGuardFree.nonce,
  snippet: snippet
    }).done(function(resp){
      if(resp && resp.success){
        renderResults($out, resp.data);
      } else {
        var msg = (resp && resp.data && resp.data.message) ? resp.data.message : 'Snippet scan failed.';
        $out.html('<div class="notice notice-error"><p>' + escapeHtml(msg) + '</p></div>');
      }
    }).fail(function(){
      $out.html('<div class="notice notice-error"><p>Request failed.</p></div>');
    });
  });

});

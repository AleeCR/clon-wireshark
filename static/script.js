        let capturing = false;
        let selectedRow = null;
        let updateInterval = null;
        let autoScroll = true;
        let userScrolled = false;
        let lastScrollTime = 0;

        // Cargar interfaces al inicializar la página
        window.onload = function() {
            loadInterfaces();
            setupScrollDetection();
        };

        function setupScrollDetection() {
            const tableContainer = document.getElementById('tableContainer');
            
            // Detectar cuando el usuario hace scroll manualmente
            tableContainer.addEventListener('scroll', function() {
                const now = Date.now();
                
                // Si el scroll fue muy reciente, probablemente es automático
                if (now - lastScrollTime < 100) return;
                
                const isAtBottom = tableContainer.scrollTop + tableContainer.clientHeight >= tableContainer.scrollHeight - 5;
                
                if (!isAtBottom && autoScroll) {
                    // Usuario hizo scroll hacia arriba
                    userScrolled = true;
                    autoScroll = false;
                    updateAutoScrollUI();
                } else if (isAtBottom && !autoScroll) {
                    // Usuario regresó al final
                    userScrolled = false;
                    autoScroll = true;
                    updateAutoScrollUI();
                }
            });
        }

        function updateAutoScrollUI() {
            const indicator = document.getElementById('scrollIndicator');
            const autoScrollBtn = document.getElementById('autoScrollBtn');
            
            if (capturing) {
                indicator.style.display = autoScroll ? 'block' : 'none';
                indicator.textContent = autoScroll ? 'Auto-scroll: ON' : 'Auto-scroll: OFF (scroll down para reactivar)';
                
                autoScrollBtn.style.display = 'block';
                autoScrollBtn.textContent = autoScroll ? '⏸️' : '▶️';
                autoScrollBtn.title = autoScroll ? 'Pausar auto-scroll' : 'Reanudar auto-scroll';
            } else {
                indicator.style.display = 'none';
                autoScrollBtn.style.display = 'none';
            }
        }

        function toggleAutoScroll() {
            autoScroll = !autoScroll;
            userScrolled = !autoScroll;
            updateAutoScrollUI();
            
            if (autoScroll) {
                scrollToBottom();
            }
        }

        function scrollToTop() {
            const tableContainer = document.getElementById('tableContainer');
            tableContainer.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function scrollToBottom() {
            const tableContainer = document.getElementById('tableContainer');
            lastScrollTime = Date.now();
            tableContainer.scrollTo({ top: tableContainer.scrollHeight, behavior: 'smooth' });
        }

        function quickStop() {
            if (capturing) {
                stopCapture();
            }
        }

        async function loadInterfaces() {
            try {
                const response = await fetch('/get_interfaces');
                const data = await response.json();
                const select = document.getElementById('interface');
                
                // Limpiar opciones existentes
                select.innerHTML = '<option value="">🔍 Seleccionar interfaz de red...</option>';
                
                if (data.interfaces && data.interfaces.length > 0) {
                    data.interfaces.forEach(iface => {
                        const option = document.createElement('option');
                        option.value = iface.name;
                        option.textContent = iface.display_name;
                        
                        // Agregar tooltip con información técnica
                        option.title = `Interfaz: ${iface.name}\nIP: ${iface.ip || 'Sin IP'}\nEstado: ${iface.status}\nTipo: ${iface.type}`;
                        
                        select.appendChild(option);
                    });
                    
                    // Seleccionar automáticamente la primera interfaz activa con IP
                    const activeInterface = data.interfaces.find(iface => 
                        iface.status === 'up' && iface.ip && iface.type !== 'loopback'
                    );
                    if (activeInterface) {
                        select.value = activeInterface.name;
                    }
                    
                } else {
                    const option = document.createElement('option');
                    option.value = '';
                    option.textContent = '❌ No se encontraron interfaces válidas';
                    select.appendChild(option);
                }
            } catch (error) {
                console.error('Error cargando interfaces:', error);
                showStatus('Error cargando interfaces de red', 'error');
                
                // Fallback en caso de error
                const select = document.getElementById('interface');
                select.innerHTML = '<option value="">❌ Error cargando interfaces</option>';
            }
        }

        async function startCapture() {
            const interface = document.getElementById('interface').value;
            const filter = document.getElementById('filter').value;
            
            if (!interface) {
                alert('Por favor selecciona una interfaz de red');
                return;
            }
            
            try {
                const response = await fetch('/start_capture', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ interface, filter })
                });
                
                const result = await response.json();
                
                if (result.status === 'success') {
                    capturing = true;
                    document.getElementById('startButton').disabled = true;
                    document.getElementById('stopButton').disabled = false;
                    showStatus('Capturando paquetes...', 'capturing');
                    
                    // Iniciar actualización automática
                    updateInterval = setInterval(updatePackets, 1000);
                } else {
                    alert(`Error: ${result.message}`);
                }
            } catch (error) {
                console.error('Error iniciando captura:', error);
                alert('Error de conexión con el servidor');
            }
        }

        async function stopCapture() {
            try {
                const response = await fetch('/stop_capture', { method: 'POST' });
                const result = await response.json();
                
                if (result.status === 'success') {
                    capturing = false;
                    document.getElementById('startButton').disabled = false;
                    document.getElementById('stopButton').disabled = true;
                    showStatus('Captura detenida', 'stopped');
                    
                    // Detener actualización automática
                    if (updateInterval) {
                        clearInterval(updateInterval);
                        updateInterval = null;
                    }
                }
            } catch (error) {
                console.error('Error deteniendo captura:', error);
                alert('Error de conexión con el servidor');
            }
        }

        async function saveCapture() {
            try {
                // Usar fetch para verificar si hay paquetes
                const response = await fetch('/get_packets');
                const data = await response.json();
                
                if (!data.packets || data.packets.length === 0) {
                    alert('No hay paquetes para guardar');
                    return;
                }
                
                // Crear enlace temporal para descarga
                const link = document.createElement('a');
                link.href = '/save_capture';
                link.download = `capture_${new Date().getTime()}.pcap`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                
                showStatus('Descargando archivo de captura...', 'capturing');
                
            } catch (error) {
                console.error('Error guardando captura:', error);
                alert('Error guardando la captura');
            }
        }

        function clearPackets() {
            if (capturing) {
                alert('Detén la captura antes de limpiar los paquetes');
                return;
            }
            
            const tbody = document.querySelector('#packetTable tbody');
            tbody.innerHTML = '';
            document.getElementById('details').textContent = 'Paquetes limpiados. Selecciona un paquete para ver detalles.';
            document.getElementById('packetCount').textContent = 'Paquetes capturados: 0';
            
            if (selectedRow) {
                selectedRow.classList.remove('selected');
                selectedRow = null;
            }
        }

        async function updatePackets() {
            if (!capturing) return;
            
            try {
                const response = await fetch('/get_packets');
                const data = await response.json();
                const tbody = document.querySelector('#packetTable tbody');
                const tableContainer = document.getElementById('tableContainer');
                
                // Solo actualizar si hay cambios
                const currentRows = tbody.children.length;
                if (data.packets.length !== currentRows) {
                    // Guardar posición de scroll actual
                    const wasAtBottom = tableContainer.scrollTop + tableContainer.clientHeight >= tableContainer.scrollHeight - 5;
                    
                    tbody.innerHTML = '';
                    
                    data.packets.forEach((packet, index) => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${packet.no}</td>
                            <td>${packet.time}</td>
                            <td>${packet.src}</td>
                            <td>${packet.dst}</td>
                            <td>${packet.protocol}</td>
                            <td>${packet.length}</td>
                            <td title="${packet.info}">${packet.info.length > 50 ? packet.info.substring(0, 50) + '...' : packet.info}</td>
                        `;
                        
                        row.onclick = () => {
                            if (selectedRow) {
                                selectedRow.classList.remove('selected');
                            }
                            row.classList.add('selected');
                            selectedRow = row;
                            showDetails(index);
                        };
                        
                        tbody.appendChild(row);
                    });
                    
                    // Actualizar contador
                    document.getElementById('packetCount').textContent = `Paquetes capturados: ${data.packets.length}`;
                    
                    // Auto-scroll solo si el usuario no ha hecho scroll manual y autoScroll está activado
                    if (autoScroll && (wasAtBottom || !userScrolled)) {
                        lastScrollTime = Date.now();
                        tableContainer.scrollTop = tableContainer.scrollHeight;
                    }
                }
            } catch (error) {
                console.error('Error actualizando paquetes:', error);
            }
        }

        async function showDetails(index) {
            try {
                const response = await fetch(`/get_packet_details/${index}`);
                const data = await response.json();
                document.getElementById('details').textContent = data.details;
            } catch (error) {
                console.error('Error obteniendo detalles:', error);
                document.getElementById('details').textContent = 'Error obteniendo detalles del paquete';
            }
        }

        function showStatus(message, type) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = `Estado: ${message}`;
            statusDiv.className = `status ${type}`;
        }

        // Atajos de teclado
        document.addEventListener('keydown', function(event) {
            if (event.ctrlKey) {
                switch(event.key) {
                    case 's':
                        event.preventDefault();
                        if (!capturing) startCapture();
                        break;
                    case 'e':
                        event.preventDefault();
                        if (capturing) stopCapture();
                        break;
                    case 'd':
                        event.preventDefault();
                        saveCapture();
                        break;
                }
            }
            // Escape para detener captura rápidamente
            if (event.key === 'Escape' && capturing) {
                stopCapture();
            }
        });
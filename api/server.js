require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const cookieParser = require('cookie-parser');
const app = express();
app.use(cors());
app.use(express.json());
app.use(cookieParser());
// Conexión a MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('Conectado a MongoDB Atlas'))
  .catch(err => console.error(err));
// Modelo de Usuario
const userSchema = new mongoose.Schema({
    nombre: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    perfil: {
        nombreCompleto: String,
        fechaNacimiento: Date,
        signoZodiacal: String,
        biografia: String,
        telefono: String,
        telegram: String,
        whatsapp: String,
        paisNacimiento: String,
        paisResidencia: String,
        ciudad: String,
        zonaHoraria: String
    }
});
const User = mongoose.model('User', userSchema);
// Modelo de Solicitud de Servicio
const serviceRequestSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    servicio: { type: String, required: true },
    precio: { type: Number, required: true },
    detalles: { type: String, required: true },
    fechaPreferida: { type: Date, required: true },
    horaPreferida: { type: String, required: true },
    contacto: { type: String, required: true },
    metodoComunicacion: { type: String, required: true },
    metodoPago: { type: String },
    detallesPago: { type: String },
    estado: { type: String, default: 'Pendiente' },
    fechaSolicitud: { type: Date, default: Date.now }
});
const ServiceRequest = mongoose.model('ServiceRequest', serviceRequestSchema);
// Modelo de Soporte
const supportTicketSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    asunto: { type: String, required: true },
    mensaje: { type: String, required: true },
    contacto: { type: String },
    estado: { type: String, default: 'Abierto' },
    fechaCreacion: { type: Date, default: Date.now },
    respuesta: { type: String },
    fechaRespuesta: { type: Date }
});
const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);
// Modelo de Conversación
const conversationSchema = new mongoose.Schema({
    usuario: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['support', 'consultation'], required: true },
    status: { type: String, enum: ['open', 'closed'], default: 'open' },
    allowUserReply: { type: Boolean, default: true },
    unreadCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now },
    lastMessage: { type: mongoose.Schema.Types.ObjectId, ref: 'Message' }
});
const Conversation = mongoose.model('Conversation', conversationSchema);
// Modelo de Mensaje
const messageSchema = new mongoose.Schema({
    conversation: { type: mongoose.Schema.Types.ObjectId, ref: 'Conversation', required: true },
    senderType: { type: String, enum: ['user', 'admin'], required: true },
    content: { type: String, required: true },
    timestamp: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', messageSchema);
// Middleware para verificar token
function verifyToken(req, res, next) {
    const token = req.cookies.token;
    console.log('Token de cookie:', token);
    
    if (!token) {
        return res.status(401).json({ mensaje: 'Token no proporcionado' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('Error al verificar token:', err);
            return res.status(401).json({ mensaje: 'Token inválido' });
        }
        req.userId = decoded.userId;
        next();
    });
}
// Middleware para verificar si es administrador
async function verifyAdmin(req, res, next) {
    try {
        const user = await User.findById(req.userId);
        if (!user || user.email !== 'admin@sabiduria2003.com') {
            return res.status(403).json({ mensaje: 'Acceso denegado' });
        }
        next();
    } catch (error) {
        res.status(500).json({ mensaje: 'Error del servidor' });
    }
}
// Rutas de la API
app.post('/api/register', async (req, res) => {
    try {
        const { nombre, email, password } = req.body;
        
        // Verificar si el usuario ya existe
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ mensaje: 'El email ya está registrado' });
        
        // Encriptar contraseña
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Crear nuevo usuario
        const user = new User({ nombre, email, password: hashedPassword });
        await user.save();
        
        res.status(201).json({ mensaje: 'Usuario creado exitosamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});
// Ruta de Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        console.log('Intento de login para:', email);
        
        // Buscar usuario
        const user = await User.findOne({ email });
        if (!user) {
            console.log('Usuario no encontrado:', email);
            return res.status(401).json({ mensaje: 'Credenciales inválidas' });
        }
        
        // Verificar contraseña
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.log('Contraseña inválida para:', email);
            return res.status(401).json({ mensaje: 'Credenciales inválidas' });
        }
        
        console.log('Login exitoso para:', email);
        
        // Generar token
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        
        // Enviar token en cookie
        res.cookie('token', token, { 
            httpOnly: true,
            maxAge: 3600000,
            secure: false,
            sameSite: 'lax'
        });
        
        console.log('Token enviado en cookie');
        
        // Verificar si es administrador
        if (email === 'admin@sabiduria2003.com') {
            console.log('Redirigiendo al panel de administración');
            res.json({ 
                nombre: user.nombre, 
                isAdmin: true,
                redirect: '/admin'
            });
        } else {
            console.log('Redirigiendo al dashboard de usuario');
            res.json({ 
                nombre: user.nombre, 
                isAdmin: false,
                redirect: '/dashboard'
            });
        }
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ mensaje: 'Error en el servidor' });
    }
});
// Rutas protegidas
app.get('/api/user', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener datos del usuario' });
    }
});
// Ruta para cerrar sesión
app.get('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/');
});
// Ruta para actualizar perfil
app.put('/api/profile', verifyToken, async (req, res) => {
    try {
        const updatedUser = await User.findByIdAndUpdate(
            req.userId,
            { $set: { perfil: req.body } },
            { new: true }
        ).select('-password');
        res.json(updatedUser);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al actualizar perfil' });
    }
});
// Ruta para crear solicitud de servicio
app.post('/api/service-request', verifyToken, async (req, res) => {
    try {
        const { servicio, precio, detalles, fechaPreferida, horaPreferida, contacto, metodoComunicacion, metodoPago, detallesPago } = req.body;
        
        const newRequest = new ServiceRequest({
            usuario: req.userId,
            servicio,
            precio,
            detalles,
            fechaPreferida,
            horaPreferida,
            contacto,
            metodoComunicacion,
            metodoPago,
            detallesPago
        });
        
        await newRequest.save();
        res.status(201).json({ mensaje: 'Solicitud de servicio creada exitosamente', newRequest });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al crear la solicitud de servicio' });
    }
});
// Ruta para obtener solicitudes de servicio del usuario actual
app.get('/api/service-requests', verifyToken, async (req, res) => {
    try {
        const requests = await ServiceRequest.find({ usuario: req.userId }).sort({ fechaSolicitud: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener las solicitudes de servicio' });
    }
});
// Ruta para crear ticket de soporte
app.post('/api/support', verifyToken, async (req, res) => {
    try {
        const { asunto, mensaje, contacto } = req.body;
        
        const newTicket = new SupportTicket({
            usuario: req.userId,
            asunto,
            mensaje,
            contacto
        });
        
        await newTicket.save();
        res.status(201).json({ mensaje: 'Ticket de soporte creado exitosamente', newTicket });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al crear el ticket de soporte' });
    }
});
// Ruta para crear conversación (solo para admin)
app.post('/api/conversations', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, type, initialMessage } = req.body;
        
        if (!userId || !type || !initialMessage) {
            return res.status(400).json({ mensaje: 'Faltan campos requeridos' });
        }
        
        // Verificar que el usuario exista
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        }
        
        // Crear nueva conversación
        const newConversation = new Conversation({
            usuario: userId,
            type,
            status: 'open',
            allowUserReply: true
        });
        
        await newConversation.save();
        
        // Crear mensaje inicial
        const newMessage = new Message({
            conversation: newConversation._id,
            senderType: 'admin',
            content: initialMessage.trim()
        });
        
        await newMessage.save();
        
        // Actualizar último mensaje
        newConversation.lastMessage = newMessage._id;
        await newConversation.save();
        
        res.status(201).json({ 
            mensaje: 'Conversación creada correctamente',
            conversation: newConversation
        });
    } catch (error) {
        console.error('Error al crear conversación:', error);
        res.status(500).json({ mensaje: 'Error al crear conversación' });
    }
});
// Rutas para el administrador
// Obtener todos los usuarios (solo admin)
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener usuarios' });
    }
});
// Obtener un usuario específico (solo admin)
app.get('/api/admin/users/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const user = await User.findById(req.params.id).select('-password');
        if (!user) {
            return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        }
        res.json(user);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener usuario' });
    }
});
// Obtener todas las solicitudes de servicio (solo admin)
app.get('/api/admin/services', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const services = await ServiceRequest.find()
            .populate('usuario', 'nombre email')
            .sort({ fechaSolicitud: -1 });
        res.json(services);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener servicios' });
    }
});
// Obtener una solicitud de servicio específica (solo admin)
app.get('/api/admin/services/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const service = await ServiceRequest.findById(req.params.id)
            .populate('usuario', 'nombre email');
        if (!service) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }
        res.json(service);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener solicitud' });
    }
});
// Actualizar estado de una solicitud de servicio (solo admin)
app.put('/api/admin/services/:id/status', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        
        const service = await ServiceRequest.findById(req.params.id);
        if (!service) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }
        
        service.estado = status;
        await service.save();
        
        res.json({ mensaje: 'Estado actualizado correctamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al actualizar estado' });
    }
});
// Obtener todos los tickets de soporte (solo admin)
app.get('/api/admin/support', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const tickets = await SupportTicket.find()
            .populate('usuario', 'nombre email')
            .sort({ fechaCreacion: -1 });
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener tickets de soporte' });
    }
});
// Obtener un ticket de soporte específico (solo admin)
app.get('/api/admin/support/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id)
            .populate('usuario', 'nombre email');
        if (!ticket) {
            return res.status(404).json({ mensaje: 'Ticket no encontrado' });
        }
        res.json(ticket);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener ticket' });
    }
});
// Cerrar ticket de soporte (solo admin)
app.post('/api/admin/support/:id/close', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ mensaje: 'Ticket no encontrado' });
        }
        
        ticket.estado = 'Cerrado';
        ticket.fechaRespuesta = new Date();
        await ticket.save();
        
        res.json({ mensaje: 'Ticket cerrado correctamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al cerrar ticket' });
    }
});
// Eliminar un ticket de soporte (solo admin)
app.delete('/api/admin/support/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const ticket = await SupportTicket.findById(req.params.id);
        if (!ticket) {
            return res.status(404).json({ mensaje: 'Ticket no encontrado' });
        }
        
        await SupportTicket.findByIdAndDelete(req.params.id);
        res.json({ mensaje: 'Ticket eliminado correctamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al eliminar ticket' });
    }
});
// Obtener todas las conversaciones (solo admin)
app.get('/api/admin/conversations', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const conversations = await Conversation.find()
            .populate('usuario', 'nombre email')
            .populate('lastMessage')
            .sort({ createdAt: -1 });
        res.json(conversations);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener conversaciones' });
    }
});
// Obtener una conversación específica (solo admin)
app.get('/api/admin/conversations/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const conversation = await Conversation.findById(req.params.id)
            .populate('usuario', 'nombre email');
        
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        res.json(conversation);
    } catch (error) {
        console.error('Error al obtener conversación:', error);
        res.status(500).json({ mensaje: 'Error al obtener conversación' });
    }
});
// Obtener mensajes de una conversación (solo admin)
app.get('/api/admin/conversations/:id/messages', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const messages = await Message.find({ conversation: req.params.id })
            .sort({ timestamp: 1 });
        
        res.json(messages);
    } catch (error) {
        console.error('Error al obtener mensajes:', error);
        res.status(500).json({ mensaje: 'Error al obtener mensajes' });
    }
});
// Enviar mensaje como administrador (solo admin)
app.post('/api/admin/conversations/:id/messages', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { content } = req.body;
        
        if (!content || content.trim() === '') {
            return res.status(400).json({ mensaje: 'El contenido del mensaje no puede estar vacío' });
        }
        
        // Verificar que la conversación exista
        const conversation = await Conversation.findById(req.params.id);
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        // Crear mensaje
        const newMessage = new Message({
            conversation: req.params.id,
            senderType: 'admin',
            content: content.trim()
        });
        
        await newMessage.save();
        
        // Actualizar último mensaje y contador de no leídos
        conversation.lastMessage = newMessage._id;
        conversation.unreadCount = (conversation.unreadCount || 0) + 1;
        await conversation.save();
        
        res.status(201).json({ 
            mensaje: 'Mensaje enviado correctamente',
            message: newMessage
        });
    } catch (error) {
        console.error('Error al enviar mensaje:', error);
        res.status(500).json({ mensaje: 'Error al enviar mensaje' });
    }
});
// Marcar conversación como leída por el administrador (solo admin)
app.post('/api/admin/conversations/:id/read', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const conversation = await Conversation.findById(req.params.id);
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        conversation.unreadCount = 0;
        await conversation.save();
        
        res.json({ mensaje: 'Conversación marcada como leída' });
    } catch (error) {
        console.error('Error al marcar conversación como leída:', error);
        res.status(500).json({ mensaje: 'Error al marcar conversación como leída' });
    }
});
// Alternar permiso de respuesta del usuario (solo admin)
app.post('/api/admin/conversations/:id/toggle-reply', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { allow } = req.body;
        
        const conversation = await Conversation.findById(req.params.id);
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        conversation.allowUserReply = allow;
        await conversation.save();
        
        res.json({ mensaje: `Permiso de respuesta ${allow ? 'permitido' : 'bloqueado'} correctamente` });
    } catch (error) {
        console.error('Error al cambiar permiso de respuesta:', error);
        res.status(500).json({ mensaje: 'Error al cambiar permiso de respuesta' });
    }
});
// Cerrar conversación (solo admin)
app.post('/api/admin/conversations/:id/close', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const conversation = await Conversation.findById(req.params.id);
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        conversation.status = 'closed';
        await conversation.save();
        
        res.json({ mensaje: 'Conversación cerrada correctamente' });
    } catch (error) {
        console.error('Error al cerrar conversación:', error);
        res.status(500).json({ mensaje: 'Error al cerrar conversación' });
    }
});
// Eliminar conversación (solo admin)
app.delete('/api/admin/conversations/:id', verifyToken, verifyAdmin, async (req, res) => {
    try {
        // Verificar que la conversación exista
        const conversation = await Conversation.findById(req.params.id);
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        // Eliminar mensajes de la conversación
        await Message.deleteMany({ conversation: req.params.id });
        
        // Eliminar conversación
        await Conversation.findByIdAndDelete(req.params.id);
        
        res.json({ mensaje: 'Conversación eliminada correctamente' });
    } catch (error) {
        console.error('Error al eliminar conversación:', error);
        res.status(500).json({ mensaje: 'Error al eliminar conversación' });
    }
});
// Crear nueva conversación (solo admin)
app.post('/api/admin/conversations', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, type, initialMessage } = req.body;
        
        if (!userId || !type || !initialMessage) {
            return res.status(400).json({ mensaje: 'Faltan campos requeridos' });
        }
        
        // Verificar que el usuario exista
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ mensaje: 'Usuario no encontrado' });
        }
        
        // Crear nueva conversación
        const newConversation = new Conversation({
            usuario: userId,
            type,
            status: 'open',
            allowUserReply: true
        });
        
        await newConversation.save();
        
        // Crear mensaje inicial
        const newMessage = new Message({
            conversation: newConversation._id,
            senderType: 'admin',
            content: initialMessage.trim()
        });
        
        await newMessage.save();
        
        // Actualizar último mensaje
        newConversation.lastMessage = newMessage._id;
        await newConversation.save();
        
        res.status(201).json({ 
            mensaje: 'Conversación creada correctamente',
            conversation: newConversation
        });
    } catch (error) {
        console.error('Error al crear conversación:', error);
        res.status(500).json({ mensaje: 'Error al crear conversación' });
    }
});
// Rutas adicionales
app.post('/api/services', verifyToken, async (req, res) => {
    try {
        console.log('Datos recibidos:', req.body);
        
        const { servicio, precio, detalles, fechaPreferida, horaPreferida, contacto, metodoComunicacion } = req.body;
        
        // Validar que todos los campos requeridos estén presentes
        if (!servicio || !precio || !detalles || !fechaPreferida || !horaPreferida || !contacto || !metodoComunicacion) {
            return res.status(400).json({ mensaje: 'Faltan campos requeridos' });
        }
        
        // Convertir fechaPreferida a objeto Date
        const fecha = new Date(fechaPreferida);
        if (isNaN(fecha.getTime())) {
            return res.status(400).json({ mensaje: 'Fecha inválida' });
        }
        
        const newRequest = new ServiceRequest({
            usuario: req.userId,
            servicio,
            precio,
            detalles,
            fechaPreferida: fecha,
            horaPreferida,
            contacto,
            metodoComunicacion
        });
        
        await newRequest.save();
        console.log('Solicitud guardada:', newRequest);
        
        res.status(201).json({ 
            mensaje: 'Solicitud creada correctamente',
            solicitud: newRequest
        });
    } catch (error) {
        console.error('Error al crear solicitud:', error);
        res.status(500).json({ mensaje: 'Error al crear solicitud', error: error.message });
    }
});
app.get('/api/services', verifyToken, async (req, res) => {
    try {
        const requests = await ServiceRequest.find({ usuario: req.userId })
            .sort({ fechaSolicitud: -1 });
        res.json(requests);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener solicitudes' });
    }
});
app.delete('/api/services/:id', verifyToken, async (req, res) => {
    try {
        const service = await ServiceRequest.findOne({ _id: req.params.id, usuario: req.userId });
        
        if (!service) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }
        
        await ServiceRequest.findByIdAndDelete(req.params.id);
        res.json({ mensaje: 'Solicitud eliminada correctamente' });
    } catch (error) {
        console.error('Error al eliminar solicitud:', error);
        res.status(500).json({ mensaje: 'Error al eliminar la solicitud' });
    }
});
app.post('/api/services/:id/confirm', verifyToken, async (req, res) => {
    try {
        const { metodoPago, detallesPago } = req.body;
        
        const service = await ServiceRequest.findOne({ _id: req.params.id, usuario: req.userId });
        
        if (!service) {
            return res.status(404).json({ mensaje: 'Solicitud no encontrada' });
        }
        
        if (service.estado !== 'Pendiente') {
            return res.status(400).json({ mensaje: 'Solo se pueden confirmar solicitudes en estado Pendiente' });
        }
        
        // Actualizar la solicitud
        service.estado = 'Procesando';
        service.metodoPago = metodoPago;
        if (detallesPago) {
            service.detallesPago = detallesPago;
        }
        
        await service.save();
        
        res.json({ mensaje: 'Solicitud confirmada correctamente' });
    } catch (error) {
        console.error('Error al confirmar solicitud:', error);
        res.status(500).json({ mensaje: 'Error al confirmar la solicitud' });
    }
});
app.post('/api/support', verifyToken, async (req, res) => {
    try {
        const { asunto, mensaje, contacto } = req.body;
        
        const newTicket = new SupportTicket({
            usuario: req.userId,
            asunto,
            mensaje,
            contacto
        });
        
        await newTicket.save();
        res.status(201).json({ mensaje: 'Ticket creado correctamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al crear ticket' });
    }
});
app.get('/api/support', verifyToken, async (req, res) => {
    try {
        const tickets = await SupportTicket.find({ usuario: req.userId })
            .sort({ fechaCreacion: -1 });
        res.json(tickets);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener tickets' });
    }
});
// Rutas para el sistema de mensajería
// Obtener conversaciones del usuario
app.get('/api/conversations', verifyToken, async (req, res) => {
    try {
        const conversations = await Conversation.find({ usuario: req.userId })
            .populate('lastMessage')
            .sort({ createdAt: -1 });
        res.json(conversations);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener conversaciones' });
    }
});
// Obtener mensajes de una conversación
app.get('/api/conversations/:id/messages', verifyToken, async (req, res) => {
    try {
        const messages = await Message.find({ conversation: req.params.id })
            .sort({ timestamp: 1 });
        res.json(messages);
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener mensajes' });
    }
});
// Enviar mensaje
app.post('/api/conversations/:id/messages', verifyToken, async (req, res) => {
    try {
        const { content } = req.body;
        
        // Verificar que la conversación pertenezca al usuario
        const conversation = await Conversation.findOne({ 
            _id: req.params.id, 
            usuario: req.userId 
        });
        
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        // Verificar si el usuario puede responder
        if (!conversation.allowUserReply) {
            return res.status(403).json({ mensaje: 'No tienes permiso para responder en esta conversación' });
        }
        
        // Crear mensaje
        const newMessage = new Message({
            conversation: req.params.id,
            senderType: 'user',
            content
        });
        
        await newMessage.save();
        
        // Actualizar última mensaje y contador de no leídos
        conversation.lastMessage = newMessage._id;
        conversation.unreadCount = (conversation.unreadCount || 0) + 1;
        await conversation.save();
        
        res.status(201).json({ mensaje: 'Mensaje enviado correctamente' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al enviar mensaje' });
    }
});
// Marcar conversación como leída
app.post('/api/conversations/:id/read', verifyToken, async (req, res) => {
    try {
        const conversation = await Conversation.findOne({ 
            _id: req.params.id, 
            usuario: req.userId 
        });
        
        if (!conversation) {
            return res.status(404).json({ mensaje: 'Conversación no encontrada' });
        }
        
        conversation.unreadCount = 0;
        await conversation.save();
        
        res.json({ mensaje: 'Conversación marcada como leída' });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al marcar como leída' });
    }
});
// Obtener mensajes no leídos
app.get('/api/messages/unread', verifyToken, async (req, res) => {
    try {
        const conversations = await Conversation.find({ 
            usuario: req.userId, 
            unreadCount: { $gt: 0 } 
        });
        
        const unreadCount = conversations.reduce((total, conv) => total + conv.unreadCount, 0);
        
        res.json({ unreadCount });
    } catch (error) {
        res.status(500).json({ mensaje: 'Error al obtener mensajes no leídos' });
    }
});
module.exports = app;

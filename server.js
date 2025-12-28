// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid'); // DOI uchun unique ID uchun qo'shildi

const app = express();
const PORT = process.env.PORT || 3000;

// Cloudinary sozlash
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Xavfsizlik sozlamalari
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com", "https://getbootstrap.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"],
      imgSrc: ["'self'", "data:", "https://res.cloudinary.com", "https://*.cloudinary.com"],
      connectSrc: ["'self'", "https://api.cloudinary.com"],
      scriptSrcAttr: ["'self'", "'unsafe-inline'"],  // Qo'shing
    }
  }
}));

// Rate limiting (faqat API uchun)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // har bir IP uchun maksimal so'rov
});
app.use('/api/', limiter);

// CORS ni yaxshilash (faqat localhost va production uchun)
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 'https://yourdomain.com' : 'http://localhost:3000',
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// MongoDB ulanishi
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://abumafia0:abumafia0@abumafia.h1trttg.mongodb.net/article2?appName=abumafia', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB ga ulandi'))
.catch(err => console.error('MongoDB ulanish xatosi:', err));

// ==================== MONGOOSE MODELLARI ====================

const UserSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  institution: { type: String, required: true },
  orcid: { type: String, default: '' },
  role: { 
    type: String, 
    enum: ['user', 'reviewer', 'admin'], 
    default: 'user' 
  },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { timestamps: true });

UserSchema.index({ email: 1 });
UserSchema.index({ role: 1 });

const ArticleSchema = new mongoose.Schema({
  title: { type: String, required: true },
  abstract: { type: String, required: true },
  keywords: [{ type: String }],
  authors: [{
    name: String,
    institution: String,
    email: String
  }],
  references: [{ type: String }],
  articleFile: {
    url: String,
    publicId: String,
    filename: String,
    size: Number
  },
  category: {
    type: String,
    enum: ['Science', 'IT', 'Medicine', 'Economics', 'Engineering', 'Social Sciences', 'Humanities', 'Other'],
    required: true
  },
  doiId: { type: String, unique: true },
  status: {
    type: String,
    enum: ['pending', 'under_review', 'accepted', 'rejected'],
    default: 'pending'  // Bepul: to'g'ridan-to'g'ri pending
  },
  assignedReviewers: [{  // Yangi: reviewer'larni assign qilish uchun
    type: mongoose.Schema.Types.ObjectId, ref: 'User'
  }],
  submissionDate: { type: Date, default: Date.now },
  reviewComments: [{
    reviewerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    comment: String,
    decision: { type: String, enum: ['accept', 'reject'] },
    date: { type: Date, default: Date.now }
  }],
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

ArticleSchema.index({ status: 1 });
ArticleSchema.index({ category: 1 });
ArticleSchema.index({ 'submittedBy': 1 });
ArticleSchema.index({ doiId: 1 }, { unique: true });
ArticleSchema.index({ 'assignedReviewers': 1 });

const models = {
  User: mongoose.model('User', UserSchema),
  Article: mongoose.model('Article', ArticleSchema)
  // Payment olib tashlandi
};

// ==================== YORDAMCHI FUNKSIYALAR ====================

const generateDOI = () => {
  const prefix = '10.1000';
  const timestamp = Date.now();
  const uniqueId = uuidv4().split('-')[0]; // Unique qilish uchun
  return `${prefix}/${timestamp}-${uniqueId}`;
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
 
  if (!token) {
    return res.status(401).json({ error: 'Token talab qilinadi' });
  }
 
  jwt.verify(token, process.env.JWT_SECRET || 'academic-platform-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Token yaroqsiz' });
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Kirish talab qilinadi' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Ruxsat berilmagan' });
    }
    next();
  };
};

// Fayl yuklash sozlamalari
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const uploadDir = 'uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Faqat PDF va DOCX fayllar ruxsat etilgan'));
    }
  }
});

// ==================== API ROUTELARI ====================

// 1. AUTHENTICATION ROUTES
// Register endpoint (rollar bo'yicha)
app.post('/api/register', async (req, res) => {
  try {
    const { fullName, email, password, institution, orcid, role = 'user' } = req.body;
    
    // Rolni cheklash: faqat user yoki reviewer
    if (!['user', 'reviewer'].includes(role)) {
      return res.status(400).json({ error: 'Faqat User yoki Reviewer roliga ro\'yxatdan o\'tish mumkin' });
    }
    
    // Email tekshirish
    const existingUser = await models.User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email allaqachon ro\'yxatdan o\'tgan' });
    }
    
    // Parol kuchliligi tekshiruvi
    if (password.length < 8 || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'Parol kamida 8 belgi, katta harf va raqam bo\'lishi kerak' });
    }
    
    // Parolni hash qilish
    const hashedPassword = await bcrypt.hash(password, 12);
    
    // Yangi foydalanuvchi yaratish (rol qo'shildi)
    const user = new models.User({
      fullName,
      email,
      password: hashedPassword,
      institution,
      orcid: orcid || '',
      role  // Tanlangan rol
    });
    
    await user.save();
    
    // JWT yaratish
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'academic-platform-secret-key',
      { expiresIn: '7d' }
    );
    
    console.log(`Yangi foydalanuvchi ro'yxatdan o'tdi: ${email} (Role: ${role})`);
    
    res.status(201).json({
      success: true,
      message: 'Ro\'yxatdan o\'tish muvaffaqiyatli',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        institution: user.institution
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
   
    // Foydalanuvchini topish
    const user = await models.User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
    }
   
    // Parolni tekshirish
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Email yoki parol noto\'g\'ri' });
    }
   
    // JWT yaratish
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'academic-platform-secret-key',
      { expiresIn: '7d' }
    );
   
    console.log(`Foydalanuvchi kirish qildi: ${email}`); // Logging qo'shildi
   
    res.json({
      success: true,
      message: 'Kirish muvaffaqiyatli',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role,
        institution: user.institution
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// 2. ARTICLE ROUTES
app.post('/api/articles', authenticateToken, upload.single('articleFile'), async (req, res) => {
  try {
    const {
      title,
      abstract,
      keywords,
      authors,
      references,
      category
    } = req.body;
   
    let parsedAuthors = [];
    try {
      parsedAuthors = JSON.parse(authors);
    } catch (e) {
      return res.status(400).json({ error: 'Mualliflar formati noto\'g\'ri' });
    }
   
    let parsedKeywords = [];
    try {
      parsedKeywords = JSON.parse(keywords);
    } catch (e) {
      parsedKeywords = keywords.split(',').map(k => k.trim());
    }
   
    let parsedReferences = [];
    try {
      parsedReferences = JSON.parse(references);
    } catch (e) {
      parsedReferences = references.split('\n').map(r => r.trim());
    }
   
    // Faylni Cloudinary ga yuklash
    let fileUploadResult = null;
    if (req.file) {
      fileUploadResult = await cloudinary.uploader.upload(req.file.path, {
        resource_type: 'auto',
        folder: 'academic-articles'
      });
     
      // Temporary faylni o'chirish
      fs.unlinkSync(req.file.path);
    }
   
    // DOI yaratish
    const doiId = generateDOI();
   
    // Maqolani yaratish (bepul: status='pending', price yo'q)
    const article = new models.Article({
      title,
      abstract,
      keywords: parsedKeywords,
      authors: parsedAuthors,
      references: parsedReferences,
      articleFile: fileUploadResult ? {
        url: fileUploadResult.secure_url,
        publicId: fileUploadResult.public_id,
        filename: req.file.originalname,
        size: req.file.size
      } : null,
      category,
      doiId,
      status: 'pending',  // Bepul: to'g'ridan-to'g'ri pending
      submittedBy: req.user.id
    });
   
    await article.save();
   
    // Avtomatik reviewer assign qilish (2 ta tasodifiy reviewer, agar mavjud bo'lsa)
    const reviewers = await models.User.find({ role: 'reviewer', isActive: true }).limit(2);
    if (reviewers.length > 0) {
      article.assignedReviewers = reviewers.map(r => r._id);
      await article.save();
      console.log(`Maqola yuklandi va ${reviewers.length} reviewer'ga assign qilindi: ${title}`);
    } else {
      console.log('Ogohlantirish: Reviewer topilmadi, admin tekshirsin');
    }
   
    console.log(`Yangi maqola yuklandi (bepul): ${title}, Article ID: ${article._id.toString()}`);
   
    res.status(201).json({
      success: true,
      message: 'Maqola muvaffaqiyatli yuklandi va reviewerlarga yuborildi',
      articleId: article._id.toString(),
      doi: doiId
    });
  } catch (error) {
    console.error('Article upload error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/articles', async (req, res) => {
  try {
    const {
      category,
      year,
      author,
      status = 'accepted',  // Default: accepted (faqat chop etilganlar)
      page = 1,
      limit = 10
    } = req.query;
   
    let filter = {};  // Status bo'yicha shartli filter
   
    if (status && status !== 'all') {
      filter.status = status;
    }
   
    if (category && category !== 'all') {
      filter.category = category;
    }
   
    if (year) {
      filter.submissionDate = {
        $gte: new Date(`${year}-01-01`),
        $lt: new Date(`${parseInt(year) + 1}-01-01`)
      };
    }
   
    if (author) {
      filter['authors.name'] = { $regex: author, $options: 'i' };
    }
   
    const articles = await models.Article.find(filter)
      .sort({ submissionDate: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .populate('submittedBy', 'fullName institution')
      .select('-reviewComments');
   
    const total = await models.Article.countDocuments(filter);
   
    res.json({
      success: true,
      articles,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get articles error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/articles/:id', async (req, res) => {
  try {
    const article = await models.Article.findById(req.params.id)
      .populate('submittedBy', 'fullName institution email')
      .populate('reviewComments.reviewerId', 'fullName')
      .populate('assignedReviewers', 'fullName email');  // Assigned reviewer'larni populate qilish
   
    if (!article) {
      return res.status(404).json({ error: 'Maqola topilmadi' });
    }
   
    res.json({
      success: true,
      article
    });
  } catch (error) {
    console.error('Get article error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// 4. REVIEWER ROUTES (yaxshilandi: faqat assigned maqolalar)
app.get('/api/reviewer/articles', authenticateToken, authorizeRole('reviewer', 'admin'), async (req, res) => {
  try {
    const { status = 'pending' } = req.query;
   
    const filter = {
      status: status === 'pending' ? 'pending' : { $in: ['pending', 'under_review'] },
      $or: [  // Faqat assigned reviewer'ga ko'rsatish
        { assignedReviewers: req.user.id },
        { assignedReviewers: { $in: [req.user.id] } }
      ]
    };
   
    const articles = await models.Article.find(filter)
      .sort({ submissionDate: 1 })
      .populate('submittedBy', 'fullName institution')
      .select('-reviewComments');
   
    res.json({
      success: true,
      articles
    });
  } catch (error) {
    console.error('Get reviewer articles error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.post('/api/reviewer/articles/:id/review', authenticateToken, authorizeRole('reviewer', 'admin'), async (req, res) => {
  try {
    const { decision, comment } = req.body;
   
    const article = await models.Article.findById(req.params.id);
    if (!article) {
      return res.status(404).json({ error: 'Maqola topilmadi' });
    }
   
    // Review qo'shish
    article.reviewComments.push({
      reviewerId: req.user.id,
      comment,
      decision
    });
   
    // Statusni yangilash (agar barcha reviewer'lar review qilgan bo'lsa, under_review ga o'tkazish mumkin, lekin oddiy: accept/reject)
    article.status = decision === 'accept' ? 'accepted' : 'rejected';
   
    await article.save();
   
    console.log(`Review qo'shildi: Article ${req.params.id}, Decision: ${decision}, Reviewer: ${req.user.email}`);
   
    res.json({
      success: true,
      message: 'Review muvaffaqiyatli qo\'shildi'
    });
  } catch (error) {
    console.error('Review submission error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// 5. ADMIN ROUTES (payment'larsiz yaxshilandi)
app.get('/api/admin/stats', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const totalUsers = await models.User.countDocuments();
    const totalArticles = await models.Article.countDocuments();
    const pendingReviews = await models.Article.countDocuments({ status: 'pending' });
   
    const articlesByCategory = await models.Article.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } }
    ]);
   
    const articlesByStatus = await models.Article.aggregate([
      { $group: { _id: '$status', count: { $sum: 1 } } }
    ]);
   
    res.json({
      success: true,
      stats: {
        totalUsers,
        totalArticles,
        pendingReviews,  // Payment o'rniga
        articlesByCategory,
        articlesByStatus
      }
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.get('/api/admin/users', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const users = await models.User.find()
      .select('-password')
      .sort({ createdAt: -1 });
   
    res.json({
      success: true,
      users
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

app.put('/api/admin/users/:id/role', authenticateToken, authorizeRole('admin'), async (req, res) => {
  try {
    const { role } = req.body;
   
    if (!['user', 'reviewer', 'admin'].includes(role)) {
      return res.status(400).json({ error: 'Noto\'g\'ri rol' });
    }
   
    const user = await models.User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    ).select('-password');
   
    if (!user) {
      return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
    }
   
    res.json({
      success: true,
      message: 'Rol muvaffaqiyatli yangilandi',
      user
    });
  } catch (error) {
    console.error('Update user role error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Payment verify o'chirildi (bepul)

// 6. USER PROFILE ROUTES
app.get('/api/profile', authenticateToken, async (req, res) => {
  try {
    const user = await models.User.findById(req.user.id).select('-password');
   
    if (!user) {
      return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
    }
   
    const userArticles = await models.Article.find({ submittedBy: req.user.id })
      .sort({ submissionDate: -1 })
      .select('title status submissionDate doiId');
   
    res.json({
      success: true,
      user,
      articles: userArticles
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Profile yangilash
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { fullName, institution, orcid } = req.body;
   
    if (!fullName || !institution) {
      return res.status(400).json({ error: 'To\'liq ism va muassasa talab qilinadi' });
    }
   
    const user = await models.User.findByIdAndUpdate(
      req.user.id,
      { 
        fullName, 
        institution, 
        orcid: orcid || '',
        updatedAt: new Date() 
      },
      { new: true }
    ).select('-password');
   
    if (!user) {
      return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
    }
   
    // JWT ni yangilash
    const token = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'academic-platform-secret-key',
      { expiresIn: '7d' }
    );
   
    console.log(`Profile yangilandi: ${user.email}`);
   
    res.json({
      success: true,
      message: 'Profile muvaffaqiyatli yangilandi',
      token,
      user
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// Parol o'zgartirish
app.put('/api/profile/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
   
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Joriy va yangi parol talab qilinadi' });
    }
   
    if (newPassword.length < 8 || !/[A-Z]/.test(newPassword) || !/[0-9]/.test(newPassword)) {
      return res.status(400).json({ error: 'Yangi parol kamida 8 belgi, katta harf va raqam bo\'lishi kerak' });
    }
   
    const user = await models.User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'Foydalanuvchi topilmadi' });
    }
   
    const validCurrent = await bcrypt.compare(currentPassword, user.password);
    if (!validCurrent) {
      return res.status(401).json({ error: 'Joriy parol noto\'g\'ri' });
    }
   
    const hashedNewPassword = await bcrypt.hash(newPassword, 12);
   
    user.password = hashedNewPassword;
    user.updatedAt = new Date();
    await user.save();
   
    console.log(`Parol o\'zgartirildi: ${user.email}`);
   
    res.json({
      success: true,
      message: 'Parol muvaffaqiyatli o\'zgartirildi'
    });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Server xatosi' });
  }
});

// ==================== HTML ROUTELARI ====================

// Asosiy sahifalar
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

// register-login ni o'chirish yoki redirect qilish
app.get('/register-login', (req, res) => {
  res.redirect('/login');
});

app.get('/articles', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'articles.html'));
});

app.get('/articles/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'article-id.html'));
});

app.get('/add-article', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'add-article.html'));
});

app.get('/profile', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/reviewer', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reviewer.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 404 Error handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err.stack);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: 'Fayl yuklash xatosi' });
  }
  res.status(500).json({
    error: 'Server xatosi',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Noma\'lum xato'
  });
});

// Serverni ishga tushirish
app.listen(PORT, () => {
  console.log(`Server ${PORT} portda ishga tushdi`);
  console.log(`http://localhost:${PORT}`);
});
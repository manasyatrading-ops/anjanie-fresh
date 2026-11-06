const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'data/products.json');
const UPLOADS = path.join(ROOT, 'uploads');

fs.mkdirSync(path.dirname(DATA), {recursive:true});
fs.mkdirSync(UPLOADS, {recursive:true});
if (!fs.existsSync(DATA)) fs.writeFileSync(DATA, '[]');

if (!process.env.ADMIN1_USER || !process.env.ADMIN1_PASS ||
    !process.env.ADMIN2_USER || !process.env.ADMIN2_PASS ||
    !process.env.SESSION_SECRET ||
    process.env.ADMIN1_PASS.startsWith('CHANGE_') ||
    process.env.ADMIN2_PASS.startsWith('CHANGE_') ||
    process.env.SESSION_SECRET.startsWith('CHANGE_') ||
    process.env.SESSION_SECRET.length < 32) {
  console.error('Check admin credentials and 32+ character SESSION_SECRET in .env');
  process.exit(1);
}

const owners = [
  {user:process.env.ADMIN1_USER,pass:process.env.ADMIN1_PASS},
  {user:process.env.ADMIN2_USER,pass:process.env.ADMIN2_PASS}
];

const sessions = new Map();

app.use(express.json({limit:'100kb'}));
app.use(express.static(path.join(ROOT,'public')));
app.use('/uploads',express.static(UPLOADS));

const loginLimit = rateLimit({
  windowMs:15*60*1000,
  limit:10,
  standardHeaders:true,
  legacyHeaders:false
});

const storage = multer.diskStorage({
  destination:(req,file,cb)=>cb(null,UPLOADS),
  filename:(req,file,cb)=>{
    const ext={
      'image/jpeg':'.jpg',
      'image/png':'.png',
      'image/webp':'.webp'
    }[file.mimetype];
    cb(null,crypto.randomUUID()+ext);
  }
});

const upload = multer({
  storage,
  limits:{fileSize:5*1024*1024,files:5},
  fileFilter:(req,file,cb)=>{
    if(['image/jpeg','image/png','image/webp'].includes(file.mimetype)) {
      cb(null,true);
    } else {
      cb(new Error('Only JPG, PNG and WebP images are allowed'));
    }
  }
});

function readProducts(){
  const products=JSON.parse(fs.readFileSync(DATA,'utf8'));
  if(!Array.isArray(products)) throw new Error('Invalid product database');
  return products;
}

function writeProducts(products){
  const temp=DATA+'.tmp';
  fs.writeFileSync(temp,JSON.stringify(products,null,2));
  fs.renameSync(temp,DATA);
}

function equal(a,b){
  const x=Buffer.from(String(a));
  const y=Buffer.from(String(b));
  return x.length===y.length && crypto.timingSafeEqual(x,y);
}

function auth(req,res,next){
  const cookies=req.headers.cookie||'';
  const match=cookies.match(/(?:^|;\s*)anjanie_session=([a-f0-9]+)/);
  const token=match&&match[1];
  const session=token&&sessions.get(token);

  if(!session||session.expires<Date.now()){
    if(token)sessions.delete(token);
    return res.status(401).json({error:'Please login again'});
  }
  next();
}

function cleanText(value,max=2000){
  return String(value||'').trim().slice(0,max);
}

function photoList(product){
  const list=Array.isArray(product.images)?product.images:[];
  if(product.image)list.unshift(product.image);
  return [...new Set(list)].filter(x=>typeof x==='string'&&x.startsWith('/uploads/'));
}

function removePhotos(photos){
  for(const photo of photos){
    const file=path.join(UPLOADS,path.basename(photo));
    if(fs.existsSync(file))fs.unlinkSync(file);
  }
}

function uploadedFiles(req){
  return req.files||[];
}

app.get('/api/status',(req,res)=>{
  res.json({store:'ANJANIÉ STYLES',status:'online'});
});

app.get('/api/products',(req,res)=>{
  try{
    res.json({success:true,products:readProducts()});
  }catch(e){
    res.status(500).json({error:'Could not read products'});
  }
});

app.post('/api/admin/login',loginLimit,(req,res)=>{
  const {username,password}=req.body||{};
  const owner=owners.find(o=>
    equal(o.user,username||'')&&equal(o.pass,password||'')
  );

  if(!owner)return res.status(401).json({error:'Invalid login details'});

  const token=crypto.randomBytes(32).toString('hex');
  sessions.set(token,{expires:Date.now()+8*60*60*1000});

  res.setHeader('Set-Cookie',
    `anjanie_session=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
  );
  res.json({success:true});
});

app.post('/api/admin/logout',auth,(req,res)=>{
  const match=(req.headers.cookie||'').match(/(?:^|;\s*)anjanie_session=([a-f0-9]+)/);
  if(match)sessions.delete(match[1]);
  res.setHeader('Set-Cookie',
    'anjanie_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
  );
  res.json({success:true});
});

app.post('/api/admin/products',auth,upload.array('images',5),(req,res)=>{
  const files=uploadedFiles(req);

  try{
    const {name,category,price,description,sizes,colours,stock}=req.body;
    const amount=Number(price);
    const quantity=Number(stock??0);

    if(!cleanText(name,150)||!cleanText(category,80)||
       !Number.isFinite(amount)||amount<=0||
       !Number.isInteger(quantity)||quantity<0){
      removePhotos(files.map(f=>'/uploads/'+f.filename));
      return res.status(400).json({error:'Enter valid name, category, price and stock'});
    }

    const products=readProducts();
    const images=files.map(f=>'/uploads/'+f.filename);

    const product={
      id:crypto.randomUUID(),
      name:cleanText(name,150),
      category:cleanText(category,80),
      price:amount,
      stock:stockAmount,
      description:cleanText(description,2000),
      sizes:cleanText(sizes,200).split(',').map(x=>x.trim()).filter(Boolean),
      colours:cleanText(colours,200).split(',').map(x=>x.trim()).filter(Boolean),
      stock:quantity,
      status:quantity>0?'active':'inactive',
      images,
      image:images[0]||''
    };

    products.push(product);
    writeProducts(products);
    res.json({success:true,product});
  }catch(e){
    removePhotos(files.map(f=>'/uploads/'+f.filename));
    res.status(500).json({error:'Could not save product'});
  }
});

app.put('/api/admin/products/:id',auth,upload.array('images',5),(req,res)=>{
  const files=uploadedFiles(req);

  try{
    const products=readProducts();
    const index=products.findIndex(p=>p.id===req.params.id);

    if(index===-1){
      removePhotos(files.map(f=>'/uploads/'+f.filename));
      return res.status(404).json({error:'Product not found'});
    }

    const old=products[index];
    const {name,category,price,description,sizes,colours,stock}=req.body;
    const amount=Number(price);
    const quantity=Number(stock);

    if(!cleanText(name,150)||!cleanText(category,80)||
       !Number.isFinite(amount)||amount<=0||
       !Number.isInteger(quantity)||quantity<0){
      removePhotos(files.map(f=>'/uploads/'+f.filename));
      return res.status(400).json({error:'Enter valid product details'});
    }

    const images=[...photoList(old),...files.map(f=>'/uploads/'+f.filename)];

    products[index]={
      ...old,
      name:cleanText(name,150),
      category:cleanText(category,80),
      price:amount,
      description:cleanText(description,2000),
      sizes:cleanText(sizes,200).split(',').map(x=>x.trim()).filter(Boolean),
      colours:cleanText(colours,200).split(',').map(x=>x.trim()).filter(Boolean),
      stock:quantity,
      status:quantity>0?'active':'inactive',
      images,
      image:images[0]||''
    };

    writeProducts(products);
    res.json({success:true,product:products[index]});
  }catch(e){
    removePhotos(files.map(f=>'/uploads/'+f.filename));
    res.status(500).json({error:'Could not update product'});
  }
});

app.delete('/api/admin/products/:id',auth,(req,res)=>{
  try{
    const products=readProducts();
    const product=products.find(p=>p.id===req.params.id);

    if(!product)return res.status(404).json({error:'Product not found'});

    writeProducts(products.filter(p=>p.id!==req.params.id));
    removePhotos(photoList(product));
    res.json({success:true});
  }catch(e){
    res.status(500).json({error:'Could not delete product'});
  }
});

app.use((err,req,res,next)=>{
  if(err instanceof multer.MulterError){
    return res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'
      ?'Each photo must be under 5 MB'
      :'Maximum 5 photos allowed'});
  }
  if(err){
    return res.status(400).json({error:err.message||'Upload failed'});
  }
  next();
});

app.listen(PORT,'0.0.0.0',()=>{
  console.log('ANJANIÉ STYLES running on port '+PORT);
});

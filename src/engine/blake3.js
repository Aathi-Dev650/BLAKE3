import { blake3 as trustedBlake3 } from '@noble/hashes/blake3';

export const IV = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
const PERM = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8];
export const FLAGS = { CHUNK_START:1, CHUNK_END:2, PARENT:4, ROOT:8 };
const rotr=(x,n)=>(x>>>n)|(x<<(32-n));
const add=(a,b)=>(a+b)>>>0;
function g(s,a,b,c,d,x,y,trace){
  const snapshot=label=>trace?.push({label,a:s[a]>>>0,b:s[b]>>>0,c:s[c]>>>0,d:s[d]>>>0,x:x>>>0,y:y>>>0});
  s[a]=add(add(s[a],s[b]),x);snapshot('a = a + b + x');s[d]=rotr(s[d]^s[a],16);snapshot('d = (d XOR a) ROTR 16');s[c]=add(s[c],s[d]);snapshot('c = c + d');s[b]=rotr(s[b]^s[c],12);snapshot('b = (b XOR c) ROTR 12');
  s[a]=add(add(s[a],s[b]),y);snapshot('a = a + b + y');s[d]=rotr(s[d]^s[a],8);snapshot('d = (d XOR a) ROTR 8');s[c]=add(s[c],s[d]);snapshot('c = c + d');s[b]=rotr(s[b]^s[c],7);snapshot('b = (b XOR c) ROTR 7');
}
function round(s,m,gs){
  const groups=[[0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15],[0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]];
  groups.forEach(([a,b,c,d],i)=>{const trace=gs?[]:null;g(s,a,b,c,d,m[i*2],m[i*2+1],trace);if(gs)gs.push({name:i<4?'COLUMN':'DIAGONAL',words:[a,b,c,d],message:[m[i*2],m[i*2+1]],trace});});
}
function words(bytes){const w=new Uint32Array(16);for(let i=0;i<bytes.length;i++)w[i>>>2]|=bytes[i]<<((i&3)*8);return w;}
function permute(m){return Uint32Array.from(PERM.map(i=>m[i]));}
function compress(cv, block, counter, blockLen, flags, capture=false){
  const s=new Uint32Array(16);s.set(cv,0);s.set(IV.subarray(0,4),8);s[12]=counter>>>0;s[13]=Math.floor(counter/0x100000000);s[14]=blockLen;s[15]=flags;
  const initial=[...s];let m=block;const rounds=[];
  for(let r=0;r<7;r++){const gs=capture?[]:null;round(s,m,gs);if(capture)rounds.push({round:r+1,state:[...s],message:[...m],gFunctions:gs});if(r<6)m=permute(m);}
  const out=new Uint32Array(16);for(let i=0;i<8;i++){out[i]=s[i]^s[i+8];out[i+8]=s[i+8]^cv[i];}
  return {out,rounds,initial};
}
class Output {
  constructor(cv,block,counter,blockLen,flags,details){Object.assign(this,{cv,block,counter,blockLen,flags,details});}
  chainingValue(){return compress(this.cv,this.block,this.counter,this.blockLen,this.flags).out.slice(0,8);}
  rootBytes(length=32){let result=new Uint8Array(length),offset=0,c=0;while(offset<length){const words16=compress(this.cv,this.block,c++,this.blockLen,this.flags|FLAGS.ROOT).out;const bytes=new Uint8Array(64);for(let i=0;i<16;i++){bytes[i*4]=words16[i];bytes[i*4+1]=words16[i]>>>8;bytes[i*4+2]=words16[i]>>>16;bytes[i*4+3]=words16[i]>>>24;}const n=Math.min(64,length-offset);result.set(bytes.subarray(0,n),offset);offset+=n;}return result;}
}
function chunkOutput(chunk,counter,record){let cv=IV;const blocks=Math.max(1,Math.ceil(chunk.length/64));for(let b=0;b<blocks;b++){const part=chunk.subarray(b*64,Math.min((b+1)*64,chunk.length)), flags=(b===0?FLAGS.CHUNK_START:0)|(b===blocks-1?FLAGS.CHUNK_END:0);const block=words(part);if(b===blocks-1){const comp=compress(cv,block,counter,part.length,flags,true);const output=new Output(cv,block,counter,part.length,flags,{rounds:comp.rounds,initial:comp.initial});record.push({kind:'chunk',index:counter,byteLength:chunk.length,blocks,output});return output;}cv=compress(cv,block,counter,part.length,flags).out.slice(0,8);}}
function parentOutput(left,right){const block=new Uint32Array(16);block.set(left,0);block.set(right,8);return new Output(IV,block,0,64,FLAGS.PARENT,null);}
export function bytesToHex(bytes){return [...bytes].map(x=>x.toString(16).padStart(2,'0')).join('');}
export function analyze(input){
  const bytes=typeof input==='string'?new TextEncoder().encode(input):input;
  const leaves=[],records=[];for(let i=0;i<bytes.length||i===0;i+=1024)leaves.push(chunkOutput(bytes.subarray(i,Math.min(i+1024,bytes.length)),i/1024,records));
  // BLAKE3's left-balanced reduction is defined by the largest power-of-two split below the subtree size.
  function subtree(start,count){
    if(count===1)return {kind:'chunk',id:`c${start}`,index:start,byteLength:records[start].byteLength,height:0,output:leaves[start],cv:leaves[start].chainingValue()};
    let split=1;while(split*2<count)split*=2;
    const left=subtree(start,split),right=subtree(start+split,count-split),output=parentOutput(left.cv,right.cv);
    return {kind:'parent',id:`p${start}-${count}`,start,count,height:Math.max(left.height,right.height)+1,left,right,output,cv:output.chainingValue()};
  }
  const tree=subtree(0,leaves.length),root=tree.output,digest=root.rootBytes(32),hex=bytesToHex(digest);
  const verified=bytesToHex(trustedBlake3(bytes));
  if(hex!==verified)throw new Error(`BLAKE3 self-check failed: ${hex} != ${verified}`);
  return {bytes,hex,verified,chunks:records,root,tree,treeHeight:tree.height,hashWords:Array.from({length:8},(_,i)=>hex.slice(i*8,i*8+8))};
}

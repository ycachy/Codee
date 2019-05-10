clear all;
addpath('H:\ida_output\');

Filepath=fullfile('H:\ida_output\');
list1=dir(Filepath);
filenamem={list1.name};
sizefile=size(filenamem);
lenn=sizefile(2);
programnumber=108; %number of program
item=200; % max embedding number
number=4800; %number of functions
M=zeros(item,programnumber,number);
X=double(M);
for i=3:lenn
    filenamem(i)
    FilePah=strcat('H:\ida_output\',filenamem(i),'\embeddd\');
    
    listt=dir(strjoin(FilePah));
   
    listlen=size(listt);
    EM=zeros(item,number);
    filename={listt.name};
    for k=3:(listlen(1));
        a=filename(k);
        a = deblank(a);
        S = regexp(char(a),'\d+(?#\.xls)','match');
        index=str2double(char(S));
        path = strjoin(strcat(FilePah,filename(k)));
        load(path); %load emdedding mat
        D=FE; %embedding mat name
        %disp(D);
        [m,n]=size(D);
        %if m>2
         if m<=item
              EM(1:m,(index+1))=(D);
              %EM(1:m,k-2)=(D);
         else
              EM(:,(index+1))=(D(1:item,1));
              %EM(:,k-2)=(D(1:item,1));
    
         end
        %end
      
    end
    
    X(:,i-2,:)=EM;
end

 kcompress=20; %compress feature

[U,S,V]=tensor_t_svd(X);

MU=ones(item,kcompress,number);
MS=ones(kcompress,kcompress,number);
MV=ones(programnumber,kcompress,number);

Ucompress=double(MU);
Scompress=double(MS);
Vcompress=double(MV);

tic;
for kk=1:number
    
    Utemp=U(:,1:kcompress,kk);
    
    Ucompress(:,:,kk)=Utemp;
   
    
end

%--------------------------------------------------------------------
%test tensor compression ratio （p) and reconstruction error ratio (e)
 for kkk=1:kcompress
     Ak=Ak+tproduct(tproduct(U(:,kkk,:),S(kkk,kkk,:)),tran(V(:,kkk,:)));
 end


 diffX=norm(X(:)-Ak(:))
 norm(X(:))
toc;
disp(num2str(toc))

%--------------------------------------------------------------------

FFE=double(ones(kcompress,programnumber,number));
Up=tran(Ucompress);
FFE=tproduct(Up,X);
save('G:/tsvd/tensor.mat', 'FFE');


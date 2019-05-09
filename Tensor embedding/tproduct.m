function C = tproduct(A,B)
% Tensor-tensor product of two 3 way tensors: C = A*B
[n1,n2,n3] = size(A);
[m1,m2,m3] = size(B);
if n2 ~= m1 || n3 ~= m3
error('Inner tensor dimensions must agree.');
end
A = fft(A,[],3);
B = fft(B,[],3);
C = zeros(n1,m2,n3);
% first frontal slice
C(:,:,1) = A(:,:,1)*B(:,:,1);
% i=2,...,halfn3
halfn3 = round(n3/2);
for i = 2 : halfn3
C(:,:,i) = A(:,:,i)*B(:,:,i);
C(:,:,n3+2-i) = conj(C(:,:,i));
end
% if n3 is even
if mod(n3,2) == 0
i = halfn3+1;
C(:,:,i) = A(:,:,i)*B(:,:,i);
end
C = ifft(C,[],3);

function Xt = tran(X)

[n1,n2,n3] = size(X);
Xt = zeros(n2,n1,n3);
Xt(:,:,1) = X(:,:,1)';
for i = 2 : n3
    Xt(:,:,i) = X(:,:,n3-i+2)';
end
